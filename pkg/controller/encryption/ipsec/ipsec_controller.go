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
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	netns "github.com/containernetworking/plugins/pkg/ns"

	"github.com/vishvananda/netlink"
	"istio.io/pkg/log"
	v1 "k8s.io/api/core/v1"
	api_errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"kmesh.net/kmesh/pkg/constants"
	kmesh_netns "kmesh.net/kmesh/pkg/controller/netns"
	v1alpha1_core "kmesh.net/kmesh/pkg/kube/apis/kmeshnodeinfo/v1alpha1"
	v1alpha1_clientset "kmesh.net/kmesh/pkg/kube/exnodeinfo/clientset/versioned/typed/kmeshnodeinfo/v1alpha1"
	informer "kmesh.net/kmesh/pkg/kube/exnodeinfo/informers/externalversions"
	v1alpha1_informers "kmesh.net/kmesh/pkg/kube/exnodeinfo/informers/externalversions/kmeshnodeinfo/v1alpha1"
	"kmesh.net/kmesh/pkg/utils"
)

const (
	MaxRetries   = 5
	ActionAdd    = "add"
	ActionDelete = "delete"
	ActionUpdate = "modify"
)

const (
	KmeshNodeInfoMapPath = "/sys/fs/bpf/bpf_kmesh_workload/map/map_of_nodeinfo"
)

type QueueItem struct {
	name   string
	action string
}

type kmeshNodeInfoMapElem struct {
	spi    uint32
	nodeid uint16
	_      uint16
}

type lpm_key struct {
	trie_key uint32
	ip       [4]uint32
}

type IpsecController struct {
	factory       informer.SharedInformerFactory
	informer      v1alpha1_informers.KmeshNodeInfoInformer
	queue         workqueue.TypedRateLimitingInterface[any]
	kniClient     v1alpha1_clientset.KmeshNodeInfoInterface
	kmeshNodeInfo v1alpha1_core.KmeshNodeInfo
	ipsecHandler  *utils.IpSecHandler
	myNode        *v1.Node
}

func NewIPsecController(k8sClientSet kubernetes.Interface) (*IpsecController, error) {
	clientSet, err := utils.GetKmeshNodeInfoClient()
	if err != nil {
		err = fmt.Errorf("failed to get kmesh node info client: %v", err)
		return nil, err
	}
	factroy := informer.NewSharedInformerFactory(clientSet, time.Second*0)

	ipsecController := &IpsecController{
		factory:      factroy,
		informer:     factroy.Kmeshnodeinfo().V1alpha1().KmeshNodeInfos(),
		queue:        workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[any]()),
		kniClient:    clientSet.KmeshnodeinfoV1alpha1().KmeshNodeInfos("kmesh-system"),
		ipsecHandler: utils.NewIpSecHandler(),
	}

	if _, err := ipsecController.informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ipsecController.handleKNIAddFunc(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			ipsecController.handleKNIUpdateFunc(oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			ipsecController.handleKNIDeleteFunc(obj)
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to add event handler to kmeshnodeinfoInformer: %v", err)
	}

	myNodeName := os.Getenv("NODE_NAME")
	myNode, err := k8sClientSet.CoreV1().Nodes().Get(context.TODO(), myNodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get kmesh node info from k8s: %v", err)
	}
	ipsecController.myNode = myNode
	return ipsecController, nil
}

func (ic *IpsecController) handleOtherNodeInfo(target *v1alpha1_core.KmeshNodeInfo) error {
	nodeNsPath := kmesh_netns.GetNodeNSpath()

	mapfd, err := ebpf.LoadPinnedMap(KmeshNodeInfoMapPath, nil)
	if err != nil {
		err = fmt.Errorf("failed to get kmesh node info map fd, %v", err)
		return err
	}
	/*
	 * src is remote host, dst is local host
	 * create xfrm rule like:
	 * ip xfrm state  add src {remoteNicIP} dst {localNicIP} proto esp {localSpi} mode tunnel reqid 1 {aead-algo} {aead-key} {aead-key-length}
	 * ip xfrm policy add src 0.0.0.0/0     dst {localCIDR}  dir in  tmpl src {remoteNicIP} dst {localNicIP} proto esp reqid 1 mode tunnel mark 0x{remoteid}00d0
	 * ip xfrm policy add src 0.0.0.0/0     dst {localCIDR}  dir fwd tmpl src {remoteNicIP} dst {localNicIP} proto esp reqid 1 mode tunnel mark 0x{remoteid}00d0
	 * remoteid = sum(remoteNicIP)
	 */
	handleInXfrm := func(netns.NetNS) error {
		for _, remoteNicIP := range target.Spec.NicIPs {
			for _, localNicIP := range ic.kmeshNodeInfo.Spec.NicIPs {
				for _, localCIDR := range ic.kmeshNodeInfo.Spec.Cirds {
					ic.ipsecHandler.SetNodeInfo(remoteNicIP, target.Spec.BootID, target.Spec.Spi)
					if err := ic.ipsecHandler.CreateXfrmRule(remoteNicIP, localNicIP, localCIDR, false); err != nil {
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
	 * ip xfrm state  add src {localNicIP} dst {remoteNicIP} proto esp spi 1 mode tunnel reqid 1 {aead-algo} {aead-key} {aead-key-length}
	 * ip xfrm policy add src 0.0.0.0/0    dst {remoteCIDR}  dir out tmpl src {localNicIP} dst {remoteNicIP} proto esp spi {spi} reqid 1 mode tunnel mark 0x{remoteid}0{spi}e0
	 */
	handleOutXfrm := func(netns.NetNS) error {
		for _, localNicIP := range ic.kmeshNodeInfo.Spec.NicIPs {
			for _, remoteNicIP := range target.Spec.NicIPs {
				for _, remoteCIDR := range target.Spec.Cirds {
					if err := ic.ipsecHandler.CreateXfrmRule(localNicIP, remoteNicIP, remoteCIDR, true); err != nil {
						return err
					}
					nodeid := ic.ipsecHandler.GetNodeID(remoteNicIP)
					if err := ic.updateKNIMapCIDR(remoteCIDR, nodeid, mapfd); err != nil {
						return err
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

func (ic *IpsecController) updateKNIMapCIDR(remoteCIDR string, nodeid uint16, mapfd *ebpf.Map) error {
	cidr := strings.Split(remoteCIDR, "/")
	prefix, _ := strconv.Atoi(cidr[1])
	kniKey := lpm_key{
		trie_key: uint32(prefix),
	}
	ip, _ := netip.ParseAddr(cidr[0])
	if ip.Is4() {
		kniKey.ip[0] = binary.LittleEndian.Uint32(ip.AsSlice())
	} else if ip.Is6() {
		tmpByte := ip.As16()
		kniKey.ip[0] = binary.LittleEndian.Uint32(tmpByte[:4])
		kniKey.ip[1] = binary.LittleEndian.Uint32(tmpByte[4:8])
		kniKey.ip[2] = binary.LittleEndian.Uint32(tmpByte[8:12])
		kniKey.ip[3] = binary.LittleEndian.Uint32(tmpByte[12:])
	}

	kniValue := kmeshNodeInfoMapElem{
		spi:    uint32(ic.ipsecHandler.Spi),
		nodeid: nodeid,
	}

	if err := mapfd.Update(&kniKey, &kniValue, ebpf.UpdateAny); err != nil {
		return err
	}
	return nil
}

func (ic *IpsecController) isMine(name string) bool {
	myNodeName := os.Getenv("NODE_NAME")
	return strings.Compare(name, myNodeName) == 0
}

func (ic *IpsecController) handleKNIAddFunc(obj interface{}) {
	kni, ok := obj.(*v1alpha1_core.KmeshNodeInfo)
	if !ok {
		log.Errorf("expected *v1alpha1_core.KmeshNodeInfo but got %T in handle add func", obj)
		return
	}

	if ic.isMine(kni.Spec.Name) {
		return
	}

	ic.queue.AddRateLimited(QueueItem{name: kni.Spec.Name,
		action: ActionAdd})
}

func (ic *IpsecController) handleKNIUpdateFunc(oldObj, newObj interface{}) {
	newKni, okNew := newObj.(*v1alpha1_core.KmeshNodeInfo)
	if !okNew {
		log.Errorf("expected *v1alpha1_core.KmeshNodeInfo but got %T in handle update new obj func", newObj)
		return
	}

	oldKni, okold := oldObj.(*v1alpha1_core.KmeshNodeInfo)
	if !okold {
		log.Errorf("expected *v1alpha1_core.KmeshNodeInfo but got %T in handle update old obj func", oldObj)
		return
	}

	if ic.isMine(newKni.Spec.Name) {
		return
	}

	if newKni.Spec.Name == oldKni.Spec.Name &&
		newKni.Spec.Spi == oldKni.Spec.Spi &&
		newKni.Spec.BootID == oldKni.Spec.BootID {
		return
	}

	ic.queue.AddRateLimited(QueueItem{name: newKni.Spec.Name,
		action: ActionUpdate})
}

func (ic *IpsecController) handleKNIDeleteFunc(obj interface{}) {
	kni, ok := obj.(*v1alpha1_core.KmeshNodeInfo)
	if !ok {
		log.Errorf("expected *v1alpha1_core.KmeshNodeInfo but got %T in handle delete func", obj)
		return
	}
	ic.queue.AddRateLimited(QueueItem{name: kni.Spec.Name,
		action: ActionDelete})
}

func (ic *IpsecController) Run(stop <-chan struct{}) {
	err := ic.ipsecHandler.LoadIPSecKeyFromFile(utils.IpSecKeyFile)
	if err != nil {
		log.Errorf(err)
		return
	}

	myNodeName := os.Getenv("NODE_NAME")
	ic.kmeshNodeInfo.Spec.Spi = ic.ipsecHandler.Spi

	ic.kmeshNodeInfo.Name = myNodeName
	ic.kmeshNodeInfo.Spec.Name = myNodeName
	ic.kmeshNodeInfo.Spec.BootID = ic.myNode.Status.NodeInfo.BootID
	ic.kmeshNodeInfo.Spec.Cirds = ic.myNode.Spec.PodCIDRs

	for _, addr := range ic.myNode.Status.Addresses {
		if strings.Compare(string(addr.Type), "InternalIP") == 0 {
			ic.kmeshNodeInfo.Spec.NicIPs = append(ic.kmeshNodeInfo.Spec.NicIPs, addr.Address)
			ic.ipsecHandler.SetNodeInfo(addr.Address, ic.kmeshNodeInfo.Spec.BootID, ic.ipsecHandler.Spi)
		}
	}

	ok := ic.attachTCforInternalNic()
	if !ok {
		return
	}

	// create xfrm in rule, current host not update my kmeshnodeinfo
	// the peer end does not use the key of the current host to send encrypted data.
	ok = ic.handleAllKmeshNodeInfo()
	if !ok {
		return
	}
	// update my kmesh node info, notify other machines that the key can be update.
	ok = ic.updateKmeshNodeInfo()
	if !ok {
		return
	}

	ic.ipsecHandler.StartWatch(ic.UpdateXfrm)

	defer ic.queue.ShutDown()
	ic.factory.Start(stop)
	if !cache.WaitForCacheSync(stop, ic.informer.Informer().HasSynced) {
		log.Error("Timed out waiting for caches to sync")
		return
	}
	for ic.processNextItem() {
	}
}

func (ic *IpsecController) Stop() {
	ic.ipsecHandler.StopWatch()
}

func (ic *IpsecController) handleAllKmeshNodeInfo() bool {
	kmeshNodeInfoList, err := ic.kniClient.List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("failed to get kmesh node info list: %v", err)
		return false
	}
	for _, node := range kmeshNodeInfoList.Items {
		if ic.isMine(node.Name) {
			continue
		}
		if err = ic.handleOtherNodeInfo(&node); err != nil {
			log.Errorf("failed to create xfrm rule for node %v: err: %v", node.Name, err)
		}
	}
	return true
}

func (ic *IpsecController) updateKmeshNodeInfo() bool {
	_, err := ic.kniClient.Create(context.TODO(), &ic.kmeshNodeInfo, metav1.CreateOptions{})
	if err != nil && !api_errors.IsAlreadyExists(err) {
		log.Errorf("failed to create kmesh node info to k8s: %v", err)
		return false
	}
	tmpUpdate, err := ic.kniClient.Get(context.TODO(), ic.kmeshNodeInfo.Name, metav1.GetOptions{})
	if err != nil {
		log.Errorf("failed to get kmesh node info to k8s: %v", err)
		return false
	}
	ic.kmeshNodeInfo.ResourceVersion = tmpUpdate.ResourceVersion
	_, err = ic.kniClient.Update(context.TODO(), &ic.kmeshNodeInfo, metav1.UpdateOptions{})
	if err != nil {
		log.Errorf("failed to update kmeshinfo, %v", err)
		return false
	}
	return true
}

func (ic *IpsecController) attachTCforInternalNic() bool {
	tc, err := utils.GetProgramByName(constants.TC_MARK_DECRYPT)
	if err != nil {
		log.Errorf("failed to get tc ebpf program in ipsec controller, %v", err)
		return false
	}

	nodeNsPath := kmesh_netns.GetNodeNSpath()
	var nicInterfaces []net.Interface

	attachFunc := func(netns.NetNS) error {
		nicInterfaces, err = net.Interfaces()
		if err != nil {
			err := fmt.Errorf("failed to get interfaces: %v", err)
			return err
		}
		for _, targetAddrString := range ic.kmeshNodeInfo.Spec.NicIPs {
			targetAddr := net.ParseIP(targetAddrString)
			for _, iface := range nicInterfaces {
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
						err = utils.AttchTCProgram(link, tc, utils.TC_DIR_INGRESS)
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
		log.Error(err)
		return false
	}

	return true
}

func (ic *IpsecController) processNextItem() bool {
	key, quit := ic.queue.Get()
	if quit {
		return false
	}
	defer ic.queue.Done(key)

	item, ok := key.(QueueItem)
	if !ok {
		log.Errorf("expected QueueItem but got %T", key)
		return true
	}

	if item.action == ActionAdd || item.action == ActionUpdate {
		kniNodeInfo, err := ic.kniClient.Get(context.TODO(), item.name, metav1.GetOptions{})
		if err != nil {
			log.Errorf("failed to get kmesh node info when process next: %v", err)
			return false
		}
		for {
			// spi not update on me, key will calc wrong, delay update when my spi update
			if kniNodeInfo.Spec.Spi != ic.ipsecHandler.Spi {
				time.Sleep(1 * time.Second)
				continue
			}
			if err := ic.handleOtherNodeInfo(kniNodeInfo); err != nil {
				log.Errorf("create xfrm out rule failed in processNextItem for node %v: %v", kniNodeInfo.Name, err)
			}
			break
		}
	}

	ic.queue.Forget(key)

	return true
}

func (ic *IpsecController) UpdateXfrm(is *utils.IpSecHandler) {
	nodeNsPath := kmesh_netns.GetNodeNSpath()

	updateXfrm := func(netns.NetNS) error {
		if err := ic.ipsecHandler.CreateNewStateFromOldByLocalNidIP(ic.kmeshNodeInfo.Spec.NicIPs); err != nil {
			log.Errorf("failed to CreateNewState, %v", err)
		}
		return nil
	}
	if err := netns.WithNetNSPath(nodeNsPath, updateXfrm); err != nil {
		return
	}

	tmpUpdate, err := ic.kniClient.Get(context.TODO(), ic.kmeshNodeInfo.Name, metav1.GetOptions{})
	if err != nil {
		log.Errorf("failed to get kmesh node info to k8s: %v", err)
		return
	}
	ic.kmeshNodeInfo.ResourceVersion = tmpUpdate.ResourceVersion
	ic.kmeshNodeInfo.Spec.Spi = ic.ipsecHandler.Spi
	_, err = ic.kniClient.Update(context.TODO(), &ic.kmeshNodeInfo, metav1.UpdateOptions{})
	if err != nil {
		log.Errorf("failed to update kmeshinfo, %v", err)
		return
	}
}
