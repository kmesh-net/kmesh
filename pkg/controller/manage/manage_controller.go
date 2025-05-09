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

package kmeshmanage

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	netns "github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"istio.io/istio/pkg/spiffe"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"kmesh.net/kmesh/pkg/constants"
	kmesh_netns "kmesh.net/kmesh/pkg/controller/netns"
	ns "kmesh.net/kmesh/pkg/controller/netns"
	kmeshsecurity "kmesh.net/kmesh/pkg/controller/security"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
)

var log = logger.NewLoggerScope("manage_controller")

const (
	MaxRetries             = 5
	ActionAddAnnotation    = "add"
	ActionDeleteAnnotation = "delete"
)

type QueueItem struct {
	podName string
	podNs   string
	action  string
}

type KmeshManageController struct {
	factory           informers.SharedInformerFactory
	podInformer       cache.SharedIndexInformer
	podLister         v1.PodLister
	namespaceInformer cache.SharedIndexInformer
	namespaceLister   v1.NamespaceLister
	queue             workqueue.TypedRateLimitingInterface[any]
	client            kubernetes.Interface
	sm                *kmeshsecurity.SecretManager
	xdpProgFd         int
	tcProgFd          int
	mode              string
}

func isPodReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func NewKmeshManageController(client kubernetes.Interface, sm *kmeshsecurity.SecretManager, xdpProgFd, tcProgFd int, mode string) (*KmeshManageController, error) {
	informerFactory := kube.NewInformerFactory(client)
	podInformer := informerFactory.Core().V1().Pods().Informer()
	podLister := informerFactory.Core().V1().Pods().Lister()

	factory := informers.NewSharedInformerFactory(client, 0)
	namespaceInformer := factory.Core().V1().Namespaces().Informer()
	namespaceLister := factory.Core().V1().Namespaces().Lister()

	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[any]())
	c := &KmeshManageController{
		podInformer:       podInformer,
		podLister:         podLister,
		factory:           factory,
		namespaceInformer: namespaceInformer,
		namespaceLister:   namespaceLister,
		queue:             queue,
		client:            client,
		sm:                sm,
		xdpProgFd:         xdpProgFd,
		tcProgFd:          tcProgFd,
		mode:              mode,
	}

	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.handlePodAdd(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			c.handlePodUpdate(oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			c.handlePodDelete(obj)
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to add event handler to podInformer: %v", err)
	}

	if _, err := namespaceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.handleNamespaceAdd(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			c.handleNamespaceUpdate(oldObj, newObj)
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to add event handler to namespaceInformer: %v", err)
	}

	return c, nil
}

func (c *KmeshManageController) handlePodAdd(obj interface{}) {
	newPod, ok := obj.(*corev1.Pod)
	if !ok {
		log.Errorf("expected *corev1.Pod but got %T", obj)
		return
	}

	namespace, err := c.namespaceLister.Get(newPod.Namespace)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return
		}
		log.Errorf("failed to get pod namespace %s: %v", newPod.Namespace, err)
		return
	}

	// enable kmesh manage
	if !utils.ShouldEnroll(newPod, namespace) {
		if utils.AnnotationEnabled(newPod.Annotations[constants.KmeshRedirectionAnnotation]) {
			c.disableKmeshManage(newPod)
		}
		return
	}
	// we need to re-link xdp in case kmesh reload xdp after restart no matter the pod has been managed by kmesh previously or not.
	c.enableKmeshManage(newPod)
}

func (c *KmeshManageController) handlePodUpdate(_, newObj interface{}) {
	pod, ok := newObj.(*corev1.Pod)
	if !ok {
		log.Errorf("expected *corev1.Pod but got %T", newObj)
		return
	}
	if pod.DeletionTimestamp != nil {
		log.Debugf("pod %s/%s is being deleted, skip remanage", pod.Namespace, pod.Name)
		return
	}
	c.handlePodAdd(newObj)
}

func (c *KmeshManageController) handlePodDelete(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			log.Errorf("couldn't get object from tombstone %#v", obj)
			return
		}
		pod, ok = tombstone.Obj.(*corev1.Pod)
		if !ok {
			log.Errorf("tombstone contained object that is not a Job %#v", obj)
			return
		}
	}

	if utils.AnnotationEnabled(pod.Annotations[constants.KmeshRedirectionAnnotation]) {
		log.Infof("%s/%s: Pod managed by Kmesh is deleted", pod.GetNamespace(), pod.GetName())
		sendCertRequest(c.sm, pod, kmeshsecurity.DELETE)
		// We donot need to do handleKmeshManage for delete, because we may have no change to execute a cmd in pod net ns.
		// And we have done this in kmesh-cni
	}
}

func (c *KmeshManageController) handleNamespaceAdd(obj interface{}) {
	ns, ok := obj.(*corev1.Namespace)
	if !ok {
		log.Errorf("Expected *corev1.Namespace but got %T", obj)
		return
	}

	if utils.ShouldEnroll(nil, ns) {
		log.Infof("Enabling Kmesh manage for all pods in namespace: %s", ns.Name)
		c.enableKmeshForPodsInNamespace(ns)
	} else {
		log.Infof("Disabling Kmesh manage for all pods in namespace: %s", ns.Name)
		c.disableKmeshForPodsInNamespace(ns)
	}
}

func (c *KmeshManageController) handleNamespaceUpdate(oldObj, newObj interface{}) {
	oldNS, okOld := oldObj.(*corev1.Namespace)
	newNS, okNew := newObj.(*corev1.Namespace)
	if !okOld || !okNew {
		log.Errorf("Expected *corev1.Namespace but got %T and %T", oldObj, newObj)
		return
	}

	// Compare labels to check if they have actually changed
	if !utils.ShouldEnroll(nil, oldNS) && utils.ShouldEnroll(nil, newNS) {
		log.Infof("Enabling Kmesh for all pods in namespace: %s", newNS.Name)
		c.enableKmeshForPodsInNamespace(newNS)
		return
	}

	if utils.ShouldEnroll(nil, oldNS) && !utils.ShouldEnroll(nil, newNS) {
		log.Infof("Disabling Kmesh for all pods in namespace: %s", newNS.Name)
		c.disableKmeshForPodsInNamespace(newNS)
	}
}

func (c *KmeshManageController) enableKmeshManage(pod *corev1.Pod) {
	sendCertRequest(c.sm, pod, kmeshsecurity.ADD)
	if !isPodReady(pod) {
		log.Debugf("Pod %s/%s is not ready, skipping Kmesh manage enable", pod.GetNamespace(), pod.GetName())
		return
	}
	log.Debugf("%s/%s: enable Kmesh manage", pod.GetNamespace(), pod.GetName())
	nspath, _ := ns.GetPodNSpath(pod)
	if err := utils.HandleKmeshManage(nspath, true); err != nil {
		log.Errorf("failed to enable Kmesh manage")
		return
	}
	c.queue.AddRateLimited(QueueItem{podName: pod.Name, podNs: pod.Namespace, action: ActionAddAnnotation})
	_ = linkXdp(nspath, c.xdpProgFd, c.mode)
	_ = linkTc(nspath, c.tcProgFd)
}

func (c *KmeshManageController) disableKmeshManage(pod *corev1.Pod) {
	sendCertRequest(c.sm, pod, kmeshsecurity.DELETE)
	log.Infof("%s/%s: disable Kmesh manage", pod.GetNamespace(), pod.GetName())
	nspath, _ := ns.GetPodNSpath(pod)
	if err := utils.HandleKmeshManage(nspath, false); err != nil {
		log.Error("failed to disable Kmesh manage")
		return
	}
	c.queue.AddRateLimited(QueueItem{podName: pod.Name, podNs: pod.Namespace, action: ActionDeleteAnnotation})
	_ = unlinkXdp(nspath, c.mode)
	_ = unlinkTc(nspath, c.tcProgFd)
}

func (c *KmeshManageController) enableKmeshForPodsInNamespace(namespace *corev1.Namespace) {
	pods, err := c.podLister.Pods(namespace.Name).List(labels.Everything())
	if err != nil {
		log.Errorf("Error listing pods in namespace %s: %v", namespace.Name, err)
		return
	}

	for _, pod := range pods {
		if utils.ShouldEnroll(pod, namespace) {
			c.enableKmeshManage(pod)
		}
	}
}

func (c *KmeshManageController) disableKmeshForPodsInNamespace(namespace *corev1.Namespace) {
	pods, err := c.podLister.Pods(namespace.Name).List(labels.Everything())
	if err != nil {
		log.Errorf("Error listing pods in namespace %s: %v", namespace.Name, err)
		return
	}

	for _, pod := range pods {
		if !utils.ShouldEnroll(pod, namespace) {
			c.disableKmeshManage(pod)
		}
	}
}

func (c *KmeshManageController) Run(stopChan <-chan struct{}) {
	defer c.queue.ShutDown()
	go c.podInformer.Run(stopChan)
	c.factory.Start(stopChan)
	if !cache.WaitForCacheSync(stopChan, c.podInformer.HasSynced, c.namespaceInformer.HasSynced) {
		log.Error("kmesh manage controller timed out waiting for caches to sync")
		return
	}

	go wait.Until(func() {
		for c.processItems() {
		}
	}, 0, stopChan)

	<-stopChan
}

func (c *KmeshManageController) processItems() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	queueItem, ok := key.(QueueItem)
	if !ok {
		log.Errorf("expected QueueItem but got %T", key)
		return true
	}

	if err := c.syncPod(queueItem); err != nil {
		if c.queue.NumRequeues(key) < MaxRetries {
			log.Errorf("failed to handle pod %s/%s action %s, err: %v, will retry", queueItem.podNs, queueItem.podName, queueItem.action, err)
			c.queue.AddRateLimited(key)
		} else {
			log.Errorf("failed to handle pod %s/%s action %s after %d retries, err: %v, giving up", queueItem.podNs, queueItem.podName, queueItem.action, MaxRetries, err)
			c.queue.Forget(key)
		}
		return true
	}

	c.queue.Forget(key)
	return true
}

func (c *KmeshManageController) syncPod(key QueueItem) error {
	pod, err := c.podLister.Pods(key.podNs).Get(key.podName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get pod %s/%s: %v", key.podNs, key.podName, err)
	}
	namespace, err := c.namespaceLister.Get(pod.Namespace)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get pod namespace %s: %v", pod.Namespace, err)
	}

	if key.action == ActionAddAnnotation && utils.ShouldEnroll(pod, namespace) {
		log.Infof("add annotation for pod %s/%s", pod.Namespace, pod.Name)
		return utils.PatchKmeshRedirectAnnotation(c.client, pod)
	} else if key.action == ActionDeleteAnnotation && !utils.ShouldEnroll(pod, namespace) {
		log.Infof("delete annotation for pod %s/%s", pod.Namespace, pod.Name)
		return utils.DelKmeshRedirectAnnotation(c.client, pod)
	}
	return nil
}

func sendCertRequest(security *kmeshsecurity.SecretManager, pod *corev1.Pod, op int) {
	if security != nil {
		Identity := spiffe.Identity{
			TrustDomain:    constants.TrustDomain,
			Namespace:      pod.Namespace,
			ServiceAccount: pod.Spec.ServiceAccountName,
		}.String()
		security.SendCertRequest(Identity, op)
	}
}

func linkXdp(netNsPath string, xdpProgFd int, mode string) error {
	// Currently only support workload mode
	if mode != constants.DualEngineMode {
		return nil
	}

	if err := netns.WithNetNSPath(netNsPath, func(_ netns.NetNS) error {
		// Get all NIC iface in a pod
		ifaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		// Link XDP prog on every iface, except loopback or not up
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
				continue
			}
			ifLink, err := netlink.LinkByName(iface.Name)
			if err != nil {
				return err
			}
			// Always let new XDP program replace the old one, to ensure that there is always only one XDP program at the same time
			if err := netlink.LinkSetXdpFd(ifLink, xdpProgFd); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		log.Errorf("Run link xdp in netNsPath %v failed, err: %v", netNsPath, err)
		return err
	}

	return nil
}

func unlinkXdp(netNsPath string, mode string) error {
	// Currently only support workload mode
	if mode != constants.DualEngineMode {
		return nil
	}

	if err := netns.WithNetNSPath(netNsPath, func(_ netns.NetNS) error {
		// Get all NIC iface in a pod
		ifaces, err := net.Interfaces()
		if err != nil {
			return err
		}

		// Unlink XDP prog on every iface, except loopback or not up
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
				continue
			}
			ifLink, err := netlink.LinkByName(iface.Name)
			if err != nil {
				return err
			}
			// Detach by using netlink since pin doesn't exist
			if err := netlink.LinkSetXdpFdWithFlags(ifLink, -1, int(link.XDPGenericMode)); err != nil {
				return fmt.Errorf("detaching generic-mode XDP program using netlink: %w", err)
			}

			if err := netlink.LinkSetXdpFdWithFlags(ifLink, -1, int(link.XDPDriverMode)); err != nil {
				return fmt.Errorf("detaching driver-mode XDP program using netlink: %w", err)
			}
		}
		return nil
	}); err != nil {
		log.Errorf("Run unlink xdp in netNsPath %v failed, err: %v", netNsPath, err)
		return err
	}

	return nil
}

func getVethPeerIndex() (ifIndex uint64, err error) {
	ifIndex = 0
	// Get all NIC iface in a pod
	ifaces, err := net.Interfaces()
	if err != nil {
		return ifIndex, err
	}
	// Link XDP prog on every iface, except loopback or not up
	for _, iface := range ifaces {
		ifIndex, err = utils.GetVethPeerIndexFromInterface(iface)
		if ifIndex == 0 {
			log.Infof("%v", err)
			continue
		}
	}
	if ifIndex == 0 {
		err = fmt.Errorf("failed to find a valid veth interface")
	}
	return ifIndex, err
}

func managleVethTc(ifIndex uint64, tcProgFd int, mode int) error {
	var (
		err  error
		link netlink.Link
	)
	if link, err = netlink.LinkByIndex(int(ifIndex)); err != nil {
		return fmt.Errorf("failed to link valid interface, %v", err)
	}

	return utils.ManageTCProgramByFd(link, tcProgFd, mode)
}

func linkTc(netNsPath string, tcProgFd int) error {
	var (
		err     error
		ifIndex uint64
	)

	if tcProgFd == -1 {
		return nil
	}

	warpGetVethPeerNum := func(_ netns.NetNS) error {
		ifIndex, err = getVethPeerIndex()
		return err
	}

	if err = netns.WithNetNSPath(netNsPath, warpGetVethPeerNum); err != nil {
		err = fmt.Errorf("Run get veth peer num in netNsPath %v failed, err: %v", netNsPath, err)
		return err
	}
	// set tc on node namespace veth peer
	if err = netns.WithNetNSPath(kmesh_netns.GetNodeNSpath(), func(_ netns.NetNS) error {
		return managleVethTc(ifIndex, tcProgFd, constants.TC_ATTACH)
	}); err != nil {
		err = fmt.Errorf("Run link tc in netNsPath %v failed, err: %v", netNsPath, err)
		return err
	}

	return nil
}

func unlinkTc(netNsPath string, tcProgFd int) error {
	var (
		err     error
		ifIndex uint64
	)

	if tcProgFd == -1 {
		return nil
	}

	warpGetVethPeerNum := func(_ netns.NetNS) error {
		ifIndex, err = getVethPeerIndex()
		return err
	}

	if err = netns.WithNetNSPath(netNsPath, warpGetVethPeerNum); err != nil {
		err = fmt.Errorf("Run get veth peer num in netNsPath %v failed, err: %v", netNsPath, err)
		return err
	}
	// set tc on node namespace veth peer
	if err := netns.WithNetNSPath(kmesh_netns.GetNodeNSpath(), func(_ netns.NetNS) error {
		return managleVethTc(ifIndex, tcProgFd, constants.TC_DETACH)
	}); err != nil {
		err = fmt.Errorf("Run link tc in netNsPath %v failed, err: %v", netNsPath, err)
		return err
	}
	return nil
}
