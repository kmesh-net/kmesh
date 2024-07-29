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
	"context"
	"fmt"
	"os"
	"strings"

	netns "github.com/containernetworking/plugins/pkg/ns"
	"istio.io/istio/pkg/spiffe"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"kmesh.net/kmesh/pkg/constants"
	ns "kmesh.net/kmesh/pkg/controller/netns"
	kmeshsecurity "kmesh.net/kmesh/pkg/controller/security"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/nets"
)

var (
	log                = logger.NewLoggerField("manage_controller")
	annotationDelPatch = []byte(fmt.Sprintf(
		`{"metadata":{"annotations":{"%s":null}}}`,
		constants.KmeshRedirectionAnnotation,
	))
	annotationAddPatch = []byte(fmt.Sprintf(
		`{"metadata":{"annotations":{"%s":"%s"}}}`,
		constants.KmeshRedirectionAnnotation,
		"enabled",
	))
)

const (
	MaxRetries             = 5
	ActionAddAnnotation    = "add"
	ActionDeleteAnnotation = "delete"
)

type QueueItem struct {
	pod    *corev1.Pod
	action string
}

func NewKmeshManageController(client kubernetes.Interface, security *kmeshsecurity.SecretManager) (*KmeshManageController, error) {
	nodeName := os.Getenv("NODE_NAME")

	informerFactory := informers.NewSharedInformerFactoryWithOptions(client, 0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fmt.Sprintf("spec.nodeName=%s", nodeName)
		}))

	podInformer := informerFactory.Core().V1().Pods().Informer()
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Errorf("expected *corev1.Pod but got %T", obj)
				return
			}
			if !shouldEnroll(client, pod) {
				return
			}

			log.Infof("%s/%s: enable Kmesh manage", pod.GetNamespace(), pod.GetName())

			nspath, _ := ns.GetPodNSpath(pod)

			if err := handleKmeshManage(nspath, true); err != nil {
				log.Errorf("failed to enable Kmesh manage")
				return
			}
			queue.AddRateLimited(QueueItem{pod: pod, action: ActionAddAnnotation})
			sendCertRequest(security, pod, kmeshsecurity.ADD)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod, okOld := oldObj.(*corev1.Pod)
			newPod, okNew := newObj.(*corev1.Pod)
			if !okOld || !okNew {
				log.Errorf("expected *corev1.Pod but got %T and %T", oldObj, newObj)
				return
			}

			//add Kmesh manage label for enable Kmesh control
			if !shouldEnroll(client, oldPod) && shouldEnroll(client, newPod) {
				log.Infof("%s/%s: enable Kmesh manage", newPod.GetNamespace(), newPod.GetName())

				nspath, _ := ns.GetPodNSpath(newPod)

				if err := handleKmeshManage(nspath, true); err != nil {
					log.Errorf("failed to enable Kmesh manage")
					return
				}
				queue.AddRateLimited(QueueItem{pod: newPod, action: ActionAddAnnotation})
				sendCertRequest(security, newPod, kmeshsecurity.ADD)
			}

			//delete Kmesh manage label for disable Kmesh control
			if shouldEnroll(client, oldPod) && !shouldEnroll(client, newPod) {
				log.Infof("%s/%s: disable Kmesh manage", newPod.GetNamespace(), newPod.GetName())

				nspath, _ := ns.GetPodNSpath(newPod)
				if err := handleKmeshManage(nspath, false); err != nil {
					log.Errorf("failed to disable Kmesh manage")
					return
				}

				queue.AddRateLimited(QueueItem{pod: newPod, action: ActionDeleteAnnotation})
				sendCertRequest(security, oldPod, kmeshsecurity.DELETE)
			}
		},
		DeleteFunc: func(obj interface{}) {
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
			if shouldEnroll(client, pod) {
				log.Infof("%s/%s: Pod managed by Kmesh is being deleted", pod.GetNamespace(), pod.GetName())
				sendCertRequest(security, pod, kmeshsecurity.DELETE)
			}
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to add event handler to podInformer: %v", err)
	}

	return &KmeshManageController{
		informerFactory: informerFactory,
		podInformer:     podInformer,
		queue:           queue,
		client:          client,
	}, nil
}

type KmeshManageController struct {
	informerFactory informers.SharedInformerFactory
	podInformer     cache.SharedIndexInformer
	queue           workqueue.RateLimitingInterface
	client          kubernetes.Interface
}

func (c *KmeshManageController) Run(stopChan <-chan struct{}) {
	defer c.queue.ShutDown()
	c.informerFactory.Start(stopChan)
	if !cache.WaitForCacheSync(stopChan, c.podInformer.HasSynced) {
		log.Error("Timed out waiting for caches to sync")
		return
	}
	for c.processItems() {
	}
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

	var err error
	if queueItem.action == ActionAddAnnotation {
		err = addKmeshAnnotation(c.client, queueItem.pod)
	} else if queueItem.action == ActionDeleteAnnotation {
		err = delKmeshAnnotation(c.client, queueItem.pod)
	}

	if err != nil {
		if c.queue.NumRequeues(key) < MaxRetries {
			log.Errorf("failed to handle pod %s/%s action %s, err: %v, will retry", queueItem.pod.Namespace, queueItem.pod.Name, queueItem.action, err)
			c.queue.AddRateLimited(key)
		} else {
			log.Errorf("failed to handle pod %s/%s action %s after %d retries, err: %v, giving up", queueItem.pod.Namespace, queueItem.pod.Name, queueItem.action, MaxRetries, err)
			c.queue.Forget(key)
		}
		return true
	}

	c.queue.Forget(key)
	return true
}

func shouldEnroll(client kubernetes.Interface, pod *corev1.Pod) bool {
	// Check if the Pod's label indicates it should be managed by Kmesh
	if strings.EqualFold(pod.Labels[constants.DataPlaneModeLabel], constants.DataPlaneModeKmesh) {
		return true
	}

	// If it is a Pod of waypoint, it should not be managed by Kmesh
	if strings.Contains(pod.Name, "waypoint") {
		return false
	}

	ns, err := client.CoreV1().Namespaces().Get(context.TODO(), pod.Namespace, metav1.GetOptions{})
	if err != nil {
		log.Errorf("failed to get namespace %s: %v", pod.Namespace, err)
		return false
	}
	// Check if the namespace's label indicates it should be managed by Kmesh
	if strings.EqualFold(ns.Labels[constants.DataPlaneModeLabel], constants.DataPlaneModeKmesh) {
		return true
	}
	return false
}

func addKmeshAnnotation(client kubernetes.Interface, pod *corev1.Pod) error {
	if value, exists := pod.Annotations[constants.KmeshRedirectionAnnotation]; exists && value == "enabled" {
		log.Debugf("Pod %s in namespace %s already has annotation %s with value %s", pod.Name, pod.Namespace, constants.KmeshRedirectionAnnotation, value)
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
	if _, exists := pod.Annotations[constants.KmeshRedirectionAnnotation]; !exists {
		log.Debugf("Pod %s in namespace %s does not have annotation %s", pod.Name, pod.Namespace, constants.KmeshRedirectionAnnotation)
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
