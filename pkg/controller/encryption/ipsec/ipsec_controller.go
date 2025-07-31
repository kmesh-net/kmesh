/*
 * Copyright The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ipsec

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"

	"github.com/cilium/ebpf"
	netns "github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"kmesh.net/kmesh/pkg/bpf/restart"
	"kmesh.net/kmesh/pkg/constants"
	kmesh_netns "kmesh.net/kmesh/pkg/controller/netns"
	"kmesh.net/kmesh/pkg/kube"
	v1alpha1 "kmesh.net/kmesh/pkg/kube/apis/kmeshnodeinfo/v1alpha1"
	v1alpha1_clientset "kmesh.net/kmesh/pkg/kube/nodeinfo/clientset/versioned/typed/kmeshnodeinfo/v1alpha1"
	informer "kmesh.net/kmesh/pkg/kube/nodeinfo/informers/externalversions"
	kmeshnodeinfov1alpha1 "kmesh.net/kmesh/pkg/kube/nodeinfo/listers/kmeshnodeinfo/v1alpha1"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
)

const (
	MaxRetries = 5
)

var log = logger.NewLoggerScope("ipsec_controller")

type lpmKey struct {
	prefix uint32
	ip     [4]uint32
}

type IPSecController struct {
	informer      cache.SharedIndexInformer
	lister        kmeshnodeinfov1alpha1.KmeshNodeInfoLister
	queue         workqueue.TypedRateLimitingInterface[any]
	knclient      v1alpha1_clientset.KmeshNodeInfoInterface
	kmeshNodeInfo v1alpha1.KmeshNodeInfo
	ipsecHandler  *IpSecHandler
	kniMap        *ebpf.Map
	tcDecryptProg *ebpf.Program
}

func NewIPsecController(k8sClientSet kubernetes.Interface, kniMap *ebpf.Map, decryptProg *ebpf.Program) (*IPSecController, error) {
	clientSet, err := kube.GetKmeshNodeInfoClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get kmesh node info client: %v", err)
	}
	factroy := informer.NewSharedInformerFactory(clientSet, 0)
	nodeinfoLister := factroy.Kmesh().V1alpha1().KmeshNodeInfos().Lister()
	nodeinfoInformer := factroy.Kmesh().V1alpha1().KmeshNodeInfos().Informer()

	ipsecController := &IPSecController{
		informer:      nodeinfoInformer,
		lister:        nodeinfoLister,
		queue:         workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[any]()),
		knclient:      clientSet.KmeshV1alpha1().KmeshNodeInfos(kube.KmeshNamespace),
		ipsecHandler:  NewIpSecHandler(),
		kniMap:        kniMap,
		tcDecryptProg: decryptProg,
	}

	// load ipsec info
	err = ipsecController.ipsecHandler.LoadIPSecKeyFromFile(IpSecKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load ipsec key from file %s: %v", IpSecKeyFile, err)
	}

	localNodeName := os.Getenv("NODE_NAME")

	localNode, err := k8sClientSet.CoreV1().Nodes().Get(context.TODO(), localNodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get kmesh node info from k8s: %v", err)
	}

	ipsecController.kmeshNodeInfo = v1alpha1.KmeshNodeInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: localNodeName,
		},
		Spec: v1alpha1.KmeshNodeInfoSpec{
			SPI:       ipsecController.ipsecHandler.Spi,
			Addresses: []string{},
			BootID:    localNode.Status.NodeInfo.BootID,
			PodCIDRs:  localNode.Spec.PodCIDRs,
		},
	}
	for _, addr := range localNode.Status.Addresses {
		if strings.Compare(string(addr.Type), string(v1.NodeInternalIP)) == 0 {
			ipsecController.kmeshNodeInfo.Spec.Addresses = append(ipsecController.kmeshNodeInfo.Spec.Addresses, addr.Address)
		}
	}

	if _, err := nodeinfoInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ipsecController.handleKNIAdd(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			ipsecController.handleKNIUpdate(oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			ipsecController.handleKNIDelete(obj)
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to add event handler to kmeshnodeinfoInformer: %v", err)
	}

	return ipsecController, nil
}

func (c *IPSecController) Run(stop <-chan struct{}) {
	defer c.queue.ShutDown()
	go c.informer.Run(stop)
	if !cache.WaitForCacheSync(stop, c.informer.HasSynced) {
		log.Error("timed out waiting for caches to sync")
		return
	}

	if err := c.attachTcDecrypt(); err != nil {
		log.Errorf("%v", err)
		return
	}

	// create xfrm in rule, current host not update my kmeshnodeinfo
	// the peer end does not use the key of the current host to send encrypted data.
	if err := c.syncAllNodeInfo(); err != nil {
		log.Errorf("failed to sync all node info: %v", err)
		return
	}

	// update my kmesh node info, notify other machines that the key can be updated.
	if err := c.updateLocalKmeshNodeInfo(); err != nil {
		log.Errorf("failed to update local node info: %v", err)
		return
	}

	if err := c.ipsecHandler.StartWatch(c.handleIpsecUpdate); err != nil {
		log.Errorf("failed to start watch file: %v", err)
		return
	}

	go wait.Until(func() {
		for c.processNextItem() {
		}
	}, 0, stop)

	<-stop
}

func (c *IPSecController) Stop() {
	c.ipsecHandler.StopWatch()
	if restart.GetStartType() == restart.Normal {
		_ = c.knclient.Delete(context.TODO(), c.kmeshNodeInfo.Name, metav1.DeleteOptions{})
		_ = c.detachTcDecrypt()
		c.CleanAllIPsec()
	}
}

func (c *IPSecController) handleTc(mode int) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get interfaces: %v", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		find, err := utils.IfaceContainIPs(iface, c.kmeshNodeInfo.Spec.Addresses)
		if err != nil {
			log.Warnf("%v", err)
			continue
		}

		if find {
			link, err := netlink.LinkByName(iface.Name)
			if err != nil {
				log.Warnf("failed to link interface %v, %v", iface, err)
				continue
			}
			err = utils.ManageTCProgram(link, c.tcDecryptProg, mode)
			if err != nil {
				log.Warnf("failed to attach tc ebpf on interface %v, %v", iface, err)
				continue
			}
		}
	}
	return nil
}

func (c *IPSecController) attachTcDecrypt() error {
	nodeNsPath := kmesh_netns.GetNodeNSpath()
	attachFunc := func(netns.NetNS) error {
		return c.handleTc(constants.TC_ATTACH)
	}

	if err := netns.WithNetNSPath(nodeNsPath, attachFunc); err != nil {
		return fmt.Errorf("failed to exec tc program attach, %v", err)
	}
	return nil
}

func (c *IPSecController) detachTcDecrypt() error {
	nodeNsPath := kmesh_netns.GetNodeNSpath()
	detachFunc := func(netns.NetNS) error {
		return c.handleTc(constants.TC_DETACH)
	}

	if err := netns.WithNetNSPath(nodeNsPath, detachFunc); err != nil {
		log.Errorf("failed to exec tc program detach, %v", err)
	}
	return nil
}

func (c *IPSecController) handleKNIAdd(obj interface{}) {
	kni, ok := obj.(*v1alpha1.KmeshNodeInfo)
	if !ok {
		log.Errorf("expected *v1alpha1_core.KmeshNodeInfo but got %T in handle add func", obj)
		return
	}

	if kni.Name == c.kmeshNodeInfo.Name {
		return
	}
	c.queue.AddRateLimited(kni.Name)
}

func (c *IPSecController) handleKNIUpdate(oldObj, newObj interface{}) {
	newKni, okNew := newObj.(*v1alpha1.KmeshNodeInfo)
	if !okNew {
		log.Errorf("expected *v1alpha1_core.KmeshNodeInfo but got %T in handle update new obj func", newObj)
		return
	}

	oldKni, okold := oldObj.(*v1alpha1.KmeshNodeInfo)
	if !okold {
		log.Errorf("expected *v1alpha1_core.KmeshNodeInfo but got %T in handle update old obj func", oldObj)
		return
	}

	if newKni.Name == c.kmeshNodeInfo.Name {
		return
	}

	if reflect.DeepEqual(oldKni.Spec, newKni.Spec) {
		return
	}

	c.queue.AddRateLimited(newKni.Name)
}

func (c *IPSecController) handleKNIDelete(obj interface{}) {
	node, ok := obj.(*v1alpha1.KmeshNodeInfo)
	if !ok {
		log.Errorf("expected *v1alpha1_core.KmeshNodeInfo but got %T in handle delete func", obj)
		return
	}
	nodeNsPath := kmesh_netns.GetNodeNSpath()
	deleteFunc := func(netns.NetNS) error {
		for _, targetIP := range node.Spec.Addresses {
			c.ipsecHandler.mutex.Lock()
			err := c.ipsecHandler.Clean(targetIP)
			c.ipsecHandler.mutex.Unlock()
			return err
		}
		return nil
	}
	err := netns.WithNetNSPath(nodeNsPath, deleteFunc)
	if err != nil {
		log.Errorf("failed to delete ipsec for node %s: %v", node.Name, err)
		return
	}
	for _, podCIDR := range node.Spec.PodCIDRs {
		c.deleteKNIMapCIDR(podCIDR, c.kniMap)
	}
}

func (c *IPSecController) handleOneNodeInfo(node *v1alpha1.KmeshNodeInfo) error {
	// can't change ipsec information when process
	c.ipsecHandler.mutex.Lock()
	defer c.ipsecHandler.mutex.Unlock()

	nodeNsPath := kmesh_netns.GetNodeNSpath()

	handleFunc := func(netns.NetNS) error {
		return c.ipsecHandler.CreateXfrmRule(&c.kmeshNodeInfo, node)
	}
	if err := netns.WithNetNSPath(nodeNsPath, handleFunc); err != nil {
		return err
	}

	for _, podCIDR := range node.Spec.PodCIDRs {
		if err := c.updateKNIMapCIDR(podCIDR, c.kniMap); err != nil {
			return fmt.Errorf("update kni map podCIDR failed, %v", err)
		}
	}

	return nil
}

func (c *IPSecController) generalKNIMapKey(remoteCIDR string) (*lpmKey, error) {
	prefix, err := netip.ParsePrefix(remoteCIDR)
	if err != nil {
		err = fmt.Errorf("update kni map podCIDR failed, podCIDR is %v, %v", remoteCIDR, err)
		return nil, err
	}
	kniKey := &lpmKey{
		prefix: uint32(prefix.Bits()),
	}

	bytes := prefix.Masked().Addr().AsSlice()
	if len(bytes) == 4 {
		kniKey.ip[0] = binary.LittleEndian.Uint32(bytes)
	} else if len(bytes) == 16 {
		kniKey.ip[0] = binary.LittleEndian.Uint32(bytes[:4])
		kniKey.ip[1] = binary.LittleEndian.Uint32(bytes[4:8])
		kniKey.ip[2] = binary.LittleEndian.Uint32(bytes[8:12])
		kniKey.ip[3] = binary.LittleEndian.Uint32(bytes[12:])
	}
	return kniKey, nil
}

func (c *IPSecController) updateKNIMapCIDR(remoteCIDR string, mapfd *ebpf.Map) error {
	kniKey, err := c.generalKNIMapKey(remoteCIDR)
	if err != nil {
		return err
	}

	kniValue := uint32(1)

	return mapfd.Update(kniKey, &kniValue, ebpf.UpdateAny)
}

func (c *IPSecController) deleteKNIMapCIDR(remoteCIDR string, mapfd *ebpf.Map) {
	kniKey, err := c.generalKNIMapKey(remoteCIDR)
	if err != nil {
		return
	}
	_ = mapfd.Delete(kniKey)
}

func (c *IPSecController) syncAllNodeInfo() error {
	nodeList, err := c.lister.KmeshNodeInfos(kube.KmeshNamespace).List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to get kmesh node info list: %v", err)
	}
	for _, node := range nodeList {
		if node.Name == c.kmeshNodeInfo.Name {
			continue
		}
		if err = c.handleOneNodeInfo(node); err != nil {
			log.Errorf("failed to create xfrm rule for node %v: err: %v", node.Name, err)
		}
	}
	return nil
}

func (c *IPSecController) updateLocalKmeshNodeInfo() error {
	node, _ := c.lister.KmeshNodeInfos(kube.KmeshNamespace).Get(c.kmeshNodeInfo.Name)
	if node == nil {
		_, err := c.knclient.Create(context.TODO(), &c.kmeshNodeInfo, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create kmesh node info: %v", err)
		}
		return nil
	}

	if reflect.DeepEqual(node.Spec, c.kmeshNodeInfo.Spec) {
		return nil
	}
	node = node.DeepCopy()
	node.Spec = c.kmeshNodeInfo.Spec
	_, err := c.knclient.Update(context.TODO(), node, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update kmeshinfo, %v", err)
	}
	return nil
}

func (c *IPSecController) CleanAllIPsec() {
	nodeNsPath := kmesh_netns.GetNodeNSpath()
	cleanFunc := func(netns.NetNS) error {
		c.ipsecHandler.Flush()
		return nil
	}

	_ = netns.WithNetNSPath(nodeNsPath, cleanFunc)
}

func (c *IPSecController) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	name, ok := key.(string)
	if !ok {
		log.Errorf("expected QueueItem but got %T", key)
		return true
	}

	node, err := c.lister.KmeshNodeInfos(kube.KmeshNamespace).Get(name)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			log.Errorf("failed to get kmesh node info %s: %v", name, err)
		}
		return true
	}
	if err := c.handleOneNodeInfo(node); err != nil {
		if c.queue.NumRequeues(key) < MaxRetries {
			log.Errorf("failed to handle other node %s err: %v, will retry", name, err)
			c.queue.AddRateLimited(key)
		} else {
			log.Errorf("failed to handle other node %s err: %v, giving up", name, err)
			c.queue.Forget(key)
		}
		return true
	}

	c.queue.Forget(key)
	return true
}

// this function need ipsechanler mutex lock before use
func (c *IPSecController) handleIpsecUpdate() {
	c.kmeshNodeInfo.Spec.SPI = c.ipsecHandler.Spi
	nodeNsPath := kmesh_netns.GetNodeNSpath()

	allNodeInfo, err := c.lister.KmeshNodeInfos(kube.KmeshNamespace).List(labels.Everything())
	if err != nil {
		log.Errorf("failed to get all kmesh node info, %v", err)
		return
	}

	updateFunc := func(netns.NetNS) error {
		for _, node := range allNodeInfo {
			if node.Name == c.kmeshNodeInfo.Name {
				continue
			}
			if err = c.ipsecHandler.CreateXfrmRule(&c.kmeshNodeInfo, node); err != nil {
				log.Errorf("%v", err)
			}
		}
		return nil
	}
	if err := netns.WithNetNSPath(nodeNsPath, updateFunc); err != nil {
		return
	}

	node, err := c.lister.KmeshNodeInfos(kube.KmeshNamespace).Get(c.kmeshNodeInfo.Name)
	if err != nil {
		log.Errorf("failed to get kmesh node info: %v", err)
		return
	}

	if node.Spec.SPI == c.ipsecHandler.Spi {
		return
	}

	update := node.DeepCopy()
	update.Spec.SPI = c.kmeshNodeInfo.Spec.SPI
	_, err = c.knclient.Update(context.TODO(), update, metav1.UpdateOptions{})
	if err != nil {
		log.Errorf("failed to update kmeshinfo, %v", err)
		return
	}
}
