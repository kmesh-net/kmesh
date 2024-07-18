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

package bypass

import (
	"fmt"
	"os"
	"time"

	netns "github.com/containernetworking/plugins/pkg/ns"
	"istio.io/api/annotation"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"kmesh.net/kmesh/pkg/constants"
	ns "kmesh.net/kmesh/pkg/controller/netns"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/nets"
	"kmesh.net/kmesh/pkg/utils"
)

var (
	log = logger.NewLoggerField("bypass")
)

const (
	DefaultInformerSyncPeriod = 30 * time.Second
	ByPassLabel               = "kmesh.net/bypass"
	ByPassValue               = "enabled"
	KmeshAnnotation           = "kmesh.net/redirection"
)

type Controller struct {
	pod             cache.SharedIndexInformer
	informerFactory informers.SharedInformerFactory
}

func NewByPassController(client kubernetes.Interface) *Controller {
	nodeName := os.Getenv("NODE_NAME")
	informerFactory := informers.NewSharedInformerFactoryWithOptions(client, DefaultInformerSyncPeriod,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fmt.Sprintf("spec.nodeName=%s", nodeName)
		}))

	podInformer := informerFactory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Errorf("expected *corev1.Pod but got %T", obj)
				return
			}
			if !shouldBypass(pod) {
				return
			}
			if !podHasSidecar(pod) {
				log.Infof("pod %s/%s does not have sidecar injected, skip", pod.GetNamespace(), pod.GetName())
				return
			}

			log.Debugf("%s/%s: enable bypass control", pod.GetNamespace(), pod.GetName())
			nspath, _ := ns.GetPodNSpath(pod)
			if err := addIptables(nspath); err != nil {
				log.Errorf("failed to add iptables rules for %s: %v", nspath, err)
				return
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod, okOld := oldObj.(*corev1.Pod)
			newPod, okNew := newObj.(*corev1.Pod)
			if !okOld || !okNew {
				log.Errorf("expected *corev1.Pod but got %T and %T", oldObj, newObj)
				return
			}

			if isPodBeingDeleted(newPod) {
				log.Debugf("%s/%s: Pod is being deleted, skipping further processing", newPod.GetNamespace(), newPod.GetName())
				return
			}

			if shouldBypass(oldPod) && !shouldBypass(newPod) {
				if podHasSidecar(newPod) {
					log.Debugf("%s/%s: enable bypass control", newPod.GetNamespace(), newPod.GetName())
					nspath, _ := ns.GetPodNSpath(newPod)
					if err := deleteIptables(nspath); err != nil {
						log.Errorf("failed to add iptables rules for %s: %v", nspath, err)
						return
					}
				}
			}
		},
		// We do not need to process delete here, because in bpf mode, it will be handled by kmesh-cni.
		// In istio sidecar mode, we do not need to delete the iptables.
	})

	c := &Controller{
		informerFactory: informerFactory,
	}

	return c
}

func (c *Controller) Run(stop <-chan struct{}) {
	c.informerFactory.Start(stop)
	if !cache.WaitForCacheSync(stop, c.pod.HasSynced) {
		log.Error("failed to wait pod cache sync")
	}
}

// checks whether there is a bypass label
func shouldBypass(pod *corev1.Pod) bool {
	return pod.Labels[ByPassLabel] == ByPassValue
}

func handleKmeshBypass(ns string, oper int) error {
	execFunc := func(netns.NetNS) error {
		/*
		 * This function is used to process pods that are marked
		 * or deleted with the bypass label on the current node.
		 * Attempt to connect to a special IP address. The
		 * connection triggers the cgroup/connect4/6 ebpf
		 * program and records the netns cookie information
		 * of the current connection. The cookie can be used
		 * to determine whether the pod is been bypass.
		 * ControlCommandIp4/6:<port> is "cipher key" for cgroup/connect4/6
		 * ebpf program. 931/932 is the specific port handled by
		 * daemon to enable/disable bypass
		 */
		port := constants.OperEnableBypass
		if oper == 0 {
			port = constants.OperDisableByPass
		}
		return nets.TriggerControlCommand(port)
	}

	if err := netns.WithNetNSPath(ns, execFunc); err != nil {
		err = fmt.Errorf("enter ns path :%v, run execFunc failed: %v", ns, err)
		return err
	}
	return nil
}

func isPodBeingDeleted(pod *corev1.Pod) bool {
	return pod.ObjectMeta.DeletionTimestamp != nil
}

func addIptables(ns string) error {
	iptArgs := [][]string{
		{"-t", "nat", "-I", "PREROUTING", "1", "-j", "RETURN"},
		{"-t", "nat", "-I", "OUTPUT", "1", "-j", "RETURN"},
	}

	execFunc := func(netns.NetNS) error {
		log.Infof("Running add iptables rule in namespace:%s", ns)
		for _, args := range iptArgs {
			if err := utils.Execute("iptables", args); err != nil {
				return fmt.Errorf("failed to exec command: iptables %v\", err: %v", args, err)
			}
		}
		return nil
	}
	if err := netns.WithNetNSPath(ns, execFunc); err != nil {
		return fmt.Errorf("enter namespace path: %v, run command failed: %v", ns, err)
	}
	return nil
}

func deleteIptables(ns string) error {
	iptArgs := [][]string{
		{"-t", "nat", "-D", "PREROUTING", "-j", "RETURN"},
		{"-t", "nat", "-D", "OUTPUT", "-j", "RETURN"},
	}

	execFunc := func(netns.NetNS) error {
		log.Infof("Running delete iptables rule in namespace:%s", ns)
		for _, args := range iptArgs {
			if err := utils.Execute("iptables", args); err != nil {
				err = fmt.Errorf("failed to exec command: iptables %v\", err: %v", args, err)
				log.Error(err)
				return err
			}
		}
		return nil
	}

	if err := netns.WithNetNSPath(ns, execFunc); err != nil {
		return fmt.Errorf("enter namespace path: %v, run command failed: %v", ns, err)
	}
	return nil
}

func podHasSidecar(pod *corev1.Pod) bool {
	if _, f := pod.GetAnnotations()[annotation.SidecarStatus.Name]; f {
		return true
	}

	return false
}

func isKmeshManaged(pod *corev1.Pod) bool {
	annotations := pod.Annotations
	if annotations != nil {
		if value, ok := annotations[constants.KmeshRedirectionAnnotation]; ok && value == "enabled" {
			return true
		}
	}
	return false
}
