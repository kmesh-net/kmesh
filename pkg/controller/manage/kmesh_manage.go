/*
 * Copyright 2024 The Kmesh Authors.
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
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	netns "github.com/containernetworking/plugins/pkg/ns"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"kmesh.net/kmesh/pkg/constants"
	ns "kmesh.net/kmesh/pkg/controller/netns"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/nets"
)

var (
	log                = logger.NewLoggerField("manage_controller")
	annotationDelPatch = []byte(fmt.Sprintf(
		`{"metadata":{"annotations":{"%s":null}}}`,
		KmeshRedirectionAnnotation,
	))
	annotationAddPatch = []byte(fmt.Sprintf(
		`{"metadata":{"annotations":{"%s":"%s"}}}`,
		KmeshRedirectionAnnotation,
		"enabled",
	))
)

const (
	DefaultInformerSyncPeriod  = 30 * time.Second
	KmeshRedirectionAnnotation = "kmesh.net/redirection"
)

func NewKmeshManageController(client kubernetes.Interface) (*KmeshManageController, error) {
	stopChan := make(chan struct{})
	nodeName := os.Getenv("NODE_NAME")

	informerFactory := informers.NewSharedInformerFactoryWithOptions(client, DefaultInformerSyncPeriod,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fmt.Sprintf("spec.nodeName=%s", nodeName)
		}))

	podInformer := informerFactory.Core().V1().Pods().Informer()

	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Errorf("expected *corev1.Pod but got %T", obj)
				return
			}

			if !shouldEnroll(pod) {
				return
			}

			log.Infof("%s/%s: enable Kmesh manage", pod.GetNamespace(), pod.GetName())

			nspath, _ := ns.GetPodNSpath(pod)

			if err := handleKmeshManage(nspath, true); err != nil {
				log.Errorf("failed to enable Kmesh manage")
				return
			}
			if err := addKmeshAnnotation(client, pod); err != nil {
				log.Errorf("failed to add Kmesh annotation, err is %v", err)
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

			//add Kmesh manage label for enable Kmesh control
			if !shouldEnroll(oldPod) && shouldEnroll(newPod) {
				log.Infof("%s/%s: enable Kmesh manage", newPod.GetNamespace(), newPod.GetName())

				nspath, _ := ns.GetPodNSpath(newPod)

				if err := handleKmeshManage(nspath, true); err != nil {
					log.Errorf("failed to enable Kmesh manage")
					return
				}
				if err := addKmeshAnnotation(client, newPod); err != nil {
					log.Errorf("failed to add Kmesh annotation, err is %v", err)
					return
				}
			}

			//delete Kmesh manage label for disable Kmesh control
			if shouldEnroll(oldPod) && !shouldEnroll(newPod) {
				log.Infof("%s/%s: disable Kmesh manage", newPod.GetNamespace(), newPod.GetName())

				nspath, _ := ns.GetPodNSpath(newPod)
				if err := handleKmeshManage(nspath, false); err != nil {
					log.Errorf("failed to disable Kmesh manage")
					return
				}

				if err := delKmeshAnnotation(client, newPod); err != nil {
					log.Errorf("failed to delete Kmesh annotation, err is %v", err)
					return
				}
			}
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to add event handler to podInformer: %v", err)
	}

	return &KmeshManageController{
		stopChan:        stopChan,
		informerFactory: informerFactory,
		podInformer:     podInformer,
	}, nil
}

type KmeshManageController struct {
	stopChan        chan struct{}
	informerFactory informers.SharedInformerFactory
	podInformer     cache.SharedIndexInformer
}

func (c *KmeshManageController) Run() {
	go func() {
		c.informerFactory.Start(c.stopChan)
		if !cache.WaitForCacheSync(c.stopChan, c.podInformer.HasSynced) {
			log.Error("Timed out waiting for caches to sync")
			return
		}
	}()
}

func isPodBeingDeleted(pod *corev1.Pod) bool {
	return pod.ObjectMeta.DeletionTimestamp != nil
}

func shouldEnroll(pod *corev1.Pod) bool {
	mode := pod.Labels[constants.DataPlaneModeLabel]
	return strings.EqualFold(mode, constants.DataPlaneModeKmesh)
}

func addKmeshAnnotation(client kubernetes.Interface, pod *corev1.Pod) error {
	if value, exists := pod.Annotations[KmeshRedirectionAnnotation]; exists && value == "enabled" {
		log.Debugf("Pod %s in namespace %s already has annotation %s with value %s", pod.Name, pod.Namespace, KmeshRedirectionAnnotation, value)
		return nil
	}
	_, err := client.CoreV1().Pods(pod.Namespace).Patch(
		context.Background(),
		pod.Name,
		k8stypes.MergePatchType,
		annotationAddPatch,
		metav1.PatchOptions{},
	)
	return err
}

func delKmeshAnnotation(client kubernetes.Interface, pod *corev1.Pod) error {
	if _, exists := pod.Annotations[KmeshRedirectionAnnotation]; !exists {
		log.Debugf("Pod %s in namespace %s does not have annotation %s", pod.Name, pod.Namespace, KmeshRedirectionAnnotation)
		return nil
	}
	_, err := client.CoreV1().Pods(pod.Namespace).Patch(
		context.Background(),
		pod.Name,
		k8stypes.MergePatchType,
		annotationDelPatch,
		metav1.PatchOptions{},
	)
	return err
}

func handleKmeshManage(ns string, op bool) error {
	execFunc := func(netns.NetNS) error {
		port := constants.OperEnableControl
		if !op {
			port = constants.OperDisableControl
		}
		return nets.TriggerControlCommand(port)
	}

	if err := netns.WithNetNSPath(ns, execFunc); err != nil {
		err = fmt.Errorf("enter ns path :%v, run execFunc failed: %v", ns, err)
		return err
	}
	return nil
}
