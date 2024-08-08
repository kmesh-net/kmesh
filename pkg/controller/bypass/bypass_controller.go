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
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"

	netns "github.com/containernetworking/plugins/pkg/ns"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	ns "kmesh.net/kmesh/pkg/controller/netns"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
	"kmesh.net/kmesh/pkg/utils/istio"
)

var (
	log = logger.NewLoggerField("bypass")
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
	informerFactory := utils.GetInformerFactory(client)

	podInformer := informerFactory.Core().V1().Pods().Informer()
	_, _ = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Errorf("expected *corev1.Pod but got %T", obj)
				return
			}
			if !istio.PodHasSidecar(pod) {
				log.Debugf("pod %s/%s does not have sidecar injected, skip", pod.GetNamespace(), pod.GetName())
				return
			}

			if !shouldBypass(pod) {
				// TODO: add delete iptables in case we missed skip bypass during kmesh restart
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
					log.Errorf("failed to delete iptables rules for %s: %v", nspath, err)
					return
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
	}
}

// checks whether there is a bypass label
func shouldBypass(pod *corev1.Pod) bool {
	return pod.Labels[ByPassLabel] == ByPassValue
}

func isPodBeingDeleted(pod *corev1.Pod) bool {
	return pod.ObjectMeta.DeletionTimestamp != nil
}

func RuleExists(args []string) (error, bool) {
	checkArgs := append(args[:2], append([]string{"-C"}, args[2:]...)...)
	log.Printf("RuleExists CheckArgs: iptables %v", checkArgs)
	cmd := exec.Command("iptables", checkArgs...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if strings.Contains(err.Error(), "Bad rule") {
			return nil, false
		} else {
			return fmt.Errorf(stderr.String()), false
		}
	}
	return nil, true
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
			utils.Execute("iptables", delargs)
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
