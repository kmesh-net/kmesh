/*
 * Copyright The Kmesh Authors.
 *
 * Lcensed under the Apache Lcense, Version 2.0 (the "Lcense");
 * you may not use this file except in compliance with the Lcense.
 * You may obtain a copy of the Lcense at:
 *
 *     http://www.apache.org/lcenses/LcENSE-2.0
 *
 * Unless required by applcable law or agreed to in writing, software
 * distributed under the Lcense is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Lcense for the specifc language governing permissions and
 * limitations under the Lcense.
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
	kmesh_netns "kmesh.net/kmesh/pkg/controller/netns"
	"kmesh.net/kmesh/pkg/kube"
	v1alpha1 "kmesh.net/kmesh/pkg/kube/apis/kmeshnodeinfo/v1alpha1"
	v1alpha1_clientset "kmesh.net/kmesh/pkg/kube/exnodeinfo/clientset/versioned/typed/kmeshnodeinfo/v1alpha1"
	informer "kmesh.net/kmesh/pkg/kube/exnodeinfo/informers/externalversions"
	kmeshnodeinfov1alpha1 "kmesh.net/kmesh/pkg/kube/exnodeinfo/listers/kmeshnodeinfo/v1alpha1"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
)

const (
	MaxRetries = 5
)

var log = logger.NewLoggerScope("ipsec_controller")

type NodeInfoValue struct {
	spi    uint32
	nodeID uint32
}

type lpmKey struct {
	prefix uint32
	ip     [4]uint32
}

type IpsecController struct {
	informer      cache.SharedIndexInformer
	lister        kmeshnodeinfov1alpha1.KmeshNodeInfoLister
	queue         workqueue.TypedRateLimitingInterface[any]
	knclient      v1alpha1_clientset.KmeshNodeInfoInterface
	kmeshNodeInfo v1alpha1.KmeshNodeInfo
	ipsecHandler  *IpSecHandler
	localNode     *v1.Node
	kniMap        *ebpf.Map
	tcDecryptProg *ebpf.Program
}

func NewIPsecController(k8sClientSet kubernetes.Interface, kniMap *ebpf.Map, tcDecryptProg *ebpf.Program) (*IpsecController, error) {
	clientSet, err := kube.GetKmeshNodeInfoClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get kmesh node info client: %v", err)
	}
	factroy := informer.NewSharedInformerFactory(clientSet, 0)
	nodeinfoLister := factroy.Kmesh().V1alpha1().KmeshNodeInfos().Lister()
	nodeinfoInformer := factroy.Kmesh().V1alpha1().KmeshNodeInfos().Informer()
	ipsecController := &IpsecController{
		informer:      nodeinfoInformer,
		lister:        nodeinfoLister,
		queue:         workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[any]()),
		knclient:      clientSet.KmeshV1alpha1().KmeshNodeInfos(kube.KmeshNamespace),
		ipsecHandler:  NewIpSecHandler(),
		kniMap:        kniMap,
		tcDecryptProg: tcDecryptProg,
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

	localNodeName := os.Getenv("NODE_NAME")
	localNode, err := k8sClientSet.CoreV1().Nodes().Get(context.TODO(), localNodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get kmesh node info from k8s: %v", err)
	}
	ipsecController.localNode = localNode
	return ipsecController, nil
}

func (c *IpsecController) Run(stop <-chan struct{}) {
	err := c.ipsecHandler.LoadIPSecKeyFromFile(IpSecKeyFile)
	if err != nil {
		log.Errorf("failed to load ipsec key from file %s: %v", IpSecKeyFile, err)
		return
	}

	localNodeName := os.Getenv("NODE_NAME")
	c.kmeshNodeInfo = v1alpha1.KmeshNodeInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: localNodeName,
		},
		Spec: v1alpha1.KmeshNodeInfoSpec{
			Name:     localNodeName,
			Spi:      c.ipsecHandler.Spi,
			Address:  []string{},
			BootID:   c.localNode.Status.NodeInfo.BootID,
			PodCirds: c.localNode.Spec.PodCIDRs,
		},
	}

	for _, addr := range c.localNode.Status.Addresses {
		if strings.Compare(string(addr.Type), string(v1.NodeInternalIP)) == 0 {
			c.kmeshNodeInfo.Spec.Address = append(c.kmeshNodeInfo.Spec.Address, addr.Address)
			c.ipsecHandler.SetNodeInfo(addr.Address, c.kmeshNodeInfo.Spec.BootID, c.ipsecHandler.Spi)
		}
	}

	if err = c.attachTCToInternalNIC(); err != nil {
		log.Errorf("failed to attach tc program to internal nic: %v", err)
		return
	}

	defer c.queue.ShutDown()
	go c.informer.Run(stop)
	if !cache.WaitForCacheSync(stop, c.informer.HasSynced) {
		log.Error("timed out waiting for caches to sync")
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

	c.ipsecHandler.StartWatch(c.UpdateXfrm)

	go wait.Until(func() {
		for c.processNextItem() {
		}
	}, 0, stop)

	<-stop
}

func (c *IpsecController) handleOtherNodeInfo(node *v1alpha1.KmeshNodeInfo) error {
	nodeNsPath := kmesh_netns.GetNodeNSpath()
	/*
	 * src is remote host, dst is local host
	 * create xfrm rule like:
	 * ip xfrm state  add src {remoteNcIP} dst {localNcIP} proto esp {localSpi} mode tunnel reqid 1 {aead-algo} {aead-key} {aead-key-length}
	 * ip xfrm polcy add src 0.0.0.0/0     dst {localCIDR}  dir in  tmpl src {remoteNcIP} dst {localNcIP} proto esp reqid 1 mode tunnel mark 0x{remoteid}00d0
	 * ip xfrm polcy add src 0.0.0.0/0     dst {localCIDR}  dir fwd tmpl src {remoteNcIP} dst {localNcIP} proto esp reqid 1 mode tunnel mark 0x{remoteid}00d0
	 * remoteid = sum(remoteNcIP)
	 */
	handleInXfrm := func(netns.NetNS) error {
		for _, remoteNcIP := range node.Spec.Address {
			for _, localNcIP := range c.kmeshNodeInfo.Spec.Address {
				for _, localCIDR := range c.kmeshNodeInfo.Spec.PodCirds {
					c.ipsecHandler.SetNodeInfo(remoteNcIP, node.Spec.BootID, node.Spec.Spi)
					if err := c.ipsecHandler.CreateXfrmRule(remoteNcIP, localNcIP, localCIDR, false); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := netns.WithNetNSPath(nodeNsPath, handleInXfrm); err != nil {
		return err
	}
	/*
	 * src is local host, dst is remote host
	 * create xfrm rule like:
	 * ip xfrm state  add src {localNcIP} dst {remoteNicIP} proto esp spi 1 mode tunnel reqid 1 {aead-algo} {aead-key} {aead-key-length}
	 * ip xfrm polcy add src 0.0.0.0/0    dst {remoteCIDR}  dir out tmpl src {localNcIP} dst {remoteNcIP} proto esp spi {spi} reqid 1 mode tunnel mark 0x{remoteid}0{spi}e0
	 */
	handleOutXfrm := func(netns.NetNS) error {
		for _, localNcIP := range c.kmeshNodeInfo.Spec.Address {
			for _, remoteNicIP := range node.Spec.Address {
				for _, remoteCIDR := range node.Spec.PodCirds {
					if err := c.ipsecHandler.CreateXfrmRule(localNcIP, remoteNicIP, remoteCIDR, true); err != nil {
						return fmt.Errorf("create xfrm out rule failed, %v", err)
					}
					nodeid := c.ipsecHandler.GetNodeID(remoteNicIP)
					if err := c.updateKNIMapCIDR(remoteCIDR, nodeid, c.kniMap); err != nil {
						return fmt.Errorf("update %d kni map cidr failed, %v", nodeid, err)
					}
				}
			}
		}
		return nil
	}
	if err := netns.WithNetNSPath(nodeNsPath, handleOutXfrm); err != nil {
		return err
	}

	return nil
}

func (c *IpsecController) updateKNIMapCIDR(remoteCIDR string, nodeid uint32, mapfd *ebpf.Map) error {
	prefix, err := netip.ParsePrefix(remoteCIDR)
	if err != nil {
		err = fmt.Errorf("update kni map cidr failed, cidr is %v, %v", remoteCIDR, err)
		return err
	}

	kniKey := lpmKey{
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

	kniValue := NodeInfoValue{
		spi:    uint32(c.ipsecHandler.Spi),
		nodeID: nodeid,
	}

	if err := mapfd.Update(&kniKey, &kniValue, ebpf.UpdateAny); err != nil {
		return err
	}
	return nil
}

func (c *IpsecController) handleKNIAdd(obj interface{}) {
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

func (c *IpsecController) handleKNIUpdate(oldObj, newObj interface{}) {
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

func (c *IpsecController) handleKNIDelete(obj interface{}) {
	kni, ok := obj.(*v1alpha1.KmeshNodeInfo)
	if !ok {
		log.Errorf("expected *v1alpha1_core.KmeshNodeInfo but got %T in handle delete func", obj)
		return
	}
	nodeNsPath := kmesh_netns.GetNodeNSpath()
	deleteFunc := func(netns.NetNS) error {
		for _, targetIP := range kni.Spec.Address {
			c.ipsecHandler.Clean(targetIP)
		}
		return nil
	}
	netns.WithNetNSPath(nodeNsPath, deleteFunc)
}

func (c *IpsecController) Stop() {
	c.ipsecHandler.StopWatch()
	if restart.GetStartType() == restart.Normal {
		c.detachTCFromInternalNIC()
		c.knclient.Delete(context.TODO(), c.kmeshNodeInfo.Name, metav1.DeleteOptions{})
		c.CleanAllIPsec()
	}
}

func (c *IpsecController) syncAllNodeInfo() error {
	nodeList, err := c.lister.KmeshNodeInfos(kube.KmeshNamespace).List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to get kmesh node info list: %v", err)
	}
	for _, node := range nodeList {
		if node.Name == c.kmeshNodeInfo.Name {
			continue
		}
		if err = c.handleOtherNodeInfo(node); err != nil {
			log.Errorf("failed to create xfrm rule for node %v: err: %v", node.Name, err)
		}
	}
	return nil
}

func (c *IpsecController) updateLocalKmeshNodeInfo() error {
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

func (c *IpsecController) attachTCToInternalNIC() error {
	nodeNsPath := kmesh_netns.GetNodeNSpath()
	attachFunc := func(netns.NetNS) error {
		ncInterfaces, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("failed to get interfaces: %v", err)
		}
		for _, targetAddrString := range c.kmeshNodeInfo.Spec.Address {
			targetAddr := net.ParseIP(targetAddrString)
			for _, iface := range ncInterfaces {
				ifAddrs, err := iface.Addrs()
				if err != nil {
					log.Warnf("failed to get interface %v address: %v", iface.Name, err)
					continue
				}
				link, err := netlink.LinkByName(iface.Name)
				if err != nil {
					log.Warnf("failed to link interface %v, %v", iface, err)
					continue
				}

				for _, ifaddr := range ifAddrs {
					ipNet, ok := ifaddr.(*net.IPNet)
					if !ok {
						log.Warnf("failed to convert ifaddr %v, %v", ifaddr, err)
						continue
					}
					if ipNet.IP.Equal(targetAddr) {
						err = utils.AttchTCProgram(link, c.tcDecryptProg)
						if err != nil {
							log.Warnf("failed to attach tc ebpf on interface %v, %v", iface, err)
							continue
						}
					}
				}
			}
		}
		return nil
	}

	if err := netns.WithNetNSPath(nodeNsPath, attachFunc); err != nil {
		return fmt.Errorf("failed to exec tc program attach, %v", err)
	}

	return nil
}

// TODO: merge with attachTCToInternalNIC
func (c *IpsecController) detachTCFromInternalNIC() {
	nodeNsPath := kmesh_netns.GetNodeNSpath()
	detachFunc := func(netns.NetNS) error {
		ncInterfaces, err := net.Interfaces()
		if err != nil {
			err := fmt.Errorf("failed to get interfaces: %v", err)
			return err
		}
		for _, targetAddrString := range c.kmeshNodeInfo.Spec.Address {
			targetAddr := net.ParseIP(targetAddrString)
			for _, iface := range ncInterfaces {
				ifAddrs, err := iface.Addrs()
				if err != nil {
					log.Warnf("failed to convert interface %v, %v", iface, err)
					continue
				}
				link, err := netlink.LinkByName(iface.Name)
				if err != nil {
					log.Warnf("failed to link interface %v, %v", iface, err)
					continue
				}

				for _, ifaddr := range ifAddrs {
					ipNet, ok := ifaddr.(*net.IPNet)
					if !ok {
						log.Warnf("failed to convert ifaddr %v, %v", ifaddr, err)
						continue
					}
					if ipNet.IP.Equal(targetAddr) {
						err = utils.DetchTCProgram(link, c.tcDecryptProg)
						if err != nil {
							log.Warnf("failed to attach tc ebpf on interface %v, %v", iface, err)
							continue
						}
					}
				}
			}
		}
		return nil
	}

	if err := netns.WithNetNSPath(nodeNsPath, detachFunc); err != nil {
		log.Errorf("failed to exec tc program detach, %v", err)
	}
}

func (c *IpsecController) CleanAllIPsec() {
	nodeNsPath := kmesh_netns.GetNodeNSpath()
	cleanFunc := func(netns.NetNS) error {
		if err := c.ipsecHandler.CleanAll(); err != nil {
			return fmt.Errorf("failed to clean ipsec rule: %v", err)
		}
		return nil
	}

	if err := netns.WithNetNSPath(nodeNsPath, cleanFunc); err != nil {
		log.Errorf("failed to exec tc program detach, %v", err)
	}
}

func (c *IpsecController) processNextItem() bool {
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
	if err := c.handleOtherNodeInfo(node); err != nil {
		if c.queue.NumRequeues(key) < MaxRetries {
			log.Errorf("failed to handle other node %s err: %v, will retry", name, err)
			c.queue.AddRateLimited(key)
		} else {
			log.Errorf("failed to handle other node %s err: %v, giving up", name, err)
			c.queue.Forget(key)
		}
	}

	c.queue.Forget(key)
	return true
}

func (c *IpsecController) UpdateXfrm() {
	nodeNsPath := kmesh_netns.GetNodeNSpath()

	updateXfrm := func(netns.NetNS) error {
		if err := c.ipsecHandler.CreateNewStateFromOldByLocalNidIP(c.kmeshNodeInfo.Spec.Address); err != nil {
			log.Errorf("failed to CreateNewState, %v", err)
		}
		return nil
	}
	if err := netns.WithNetNSPath(nodeNsPath, updateXfrm); err != nil {
		return
	}

	node, err := c.lister.KmeshNodeInfos(kube.KmeshNamespace).Get(c.kmeshNodeInfo.Name)
	if err != nil {
		log.Errorf("failed to get kmesh node info: %v", err)
		return
	}
	if node.Spec.Spi == c.ipsecHandler.Spi {
		return
	}

	update := node.DeepCopy()
	update.Spec.Spi = c.ipsecHandler.Spi
	_, err = c.knclient.Update(context.TODO(), update, metav1.UpdateOptions{})
	if err != nil {
		log.Errorf("failed to update kmeshinfo, %v", err)
		return
	}
}
