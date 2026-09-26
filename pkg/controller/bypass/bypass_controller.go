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
	"time"

	netns "github.com/containernetworking/plugins/pkg/ns"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	ns "kmesh.net/kmesh/pkg/controller/netns"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
	"kmesh.net/kmesh/pkg/utils/istio"
)

var (
	log = logger.NewLoggerScope("bypass")
)

const (
	DefaultInformerSyncPeriod = 30 * time.Second
	ByPassLabel               = "kmesh.net/bypass"
	ByPassValue               = "enabled"
)

type Controller struct {
	pod             cache.SharedIndexInformer
	informerFactory informers.SharedInformerFactory
}

func NewByPassController(client kubernetes.Interface) *Controller {
	informerFactory := kube.NewInformerFactory(client)

	podInformer := informerFactory.Core().V1().Pods().Informer()
	_, _ = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Errorf("expected *corev1.Pod but got %T", obj)
				return
			}
			if !istio.PodHasSidecar(pod) {
				log.Infof("pod %s/%s does not have sidecar injected, skip", pod.GetNamespace(), pod.GetName())
				return
			}

			if !shouldBypass(pod) {
				// On Kmesh restart the informer re-lists all existing pods and fires
				// AddFunc for each of them. If a pod previously had the bypass label
				// (and thus has PREROUTING/OUTPUT RETURN rules) but the label has since
				// been removed, we must clean up those stale rules here.
				nspath, err := ns.GetPodNSpath(pod)
				if err != nil {
					// Pod may still be initialising; this is not an error.
					log.Debugf("failed to get netns for pod %s/%s (may still be creating): %v", pod.Namespace, pod.Name, err)
					return
				}
				if err := deleteIptables(nspath); err != nil {
					// Not an error: the rules simply may not exist for pods that were
					// never bypassed. Log at Debug to avoid noise.
					log.Debugf("deleteIptables for %s/%s: %v (may already be clean)", pod.Namespace, pod.Name, err)
				}
				return
			}

			log.Infof("%s/%s: bypass sidecar control", pod.GetNamespace(), pod.GetName())
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

			if !istio.PodHasSidecar(newPod) {
				log.Debugf("pod %s/%s does not have a sidecar", newPod.GetNamespace(), newPod.GetName())
				return
			}

			if shouldBypass(oldPod) && !shouldBypass(newPod) {
				log.Infof("%s/%s: restore sidecar control", newPod.GetNamespace(), newPod.GetName())
				nspath, _ := ns.GetPodNSpath(newPod)
				if err := deleteIptables(nspath); err != nil {
					// Warn rather than error: one or both rules may already be absent
					// (e.g. node reboot, manual removal). Reconciliation continues.
					log.Warnf("failed to delete iptables rules for %s: %v", nspath, err)
				}
			}
			if !shouldBypass(oldPod) && shouldBypass(newPod) {
				log.Infof("%s/%s: bypass sidecar control", newPod.GetNamespace(), newPod.GetName())
				nspath, _ := ns.GetPodNSpath(newPod)
				if err := addIptables(nspath); err != nil {
					log.Errorf("failed to add iptables rules for %s: %v", nspath, err)
					return
				}
			}
		},
		// We do not need to process delete here, because
		// in istio sidecar mode, we do not need to delete the iptables.
	})

	c := &Controller{
		informerFactory: informerFactory,
		pod:             podInformer,
	}

	return c
}

func (c *Controller) Run(stop <-chan struct{}) {
	c.informerFactory.Start(stop)
	if !cache.WaitForCacheSync(stop, c.pod.HasSynced) {
		log.Error("failed to wait pod cache sync")
		return
	}
}

// checks whether there is a bypass label
func shouldBypass(pod *corev1.Pod) bool {
	return pod.Labels[ByPassLabel] == ByPassValue
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
		//To avoid iptables rules being added multiple times due to problems with k8s resource synchronization
		delIptArgs := [][]string{
			{"-t", "nat", "-D", "PREROUTING", "-j", "RETURN"},
			{"-t", "nat", "-D", "OUTPUT", "-j", "RETURN"},
		}
		for _, delargs := range delIptArgs {
			_ = utils.Execute("iptables", delargs)
		}
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
		log.Debugf("Running delete iptables rule in namespace:%s", ns)
		// Ignore individual iptables errors (e.g., rule does not exist).
		// This makes the function safely idempotent and prevents log spam.
		// This mirrors how addIptables handles its delete-before-insert step.
		for _, args := range iptArgs {
			_ = utils.Execute("iptables", args)
		}
		return nil
	}

	if err := netns.WithNetNSPath(ns, execFunc); err != nil {
		return fmt.Errorf("enter namespace path: %v, run command failed: %v", ns, err)
	}
	return nil
}
