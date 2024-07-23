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

	"istio.io/istio/pkg/spiffe"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"kmesh.net/kmesh/pkg/constants"
	ns "kmesh.net/kmesh/pkg/controller/netns"
	kmeshsecurity "kmesh.net/kmesh/pkg/controller/security"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
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
	podName string
	podNs   string
	action  string
}

type KmeshManageController struct {
	// TODO: share pod informer with bypass?
	informerFactory   informers.SharedInformerFactory
	factory           informers.SharedInformerFactory
	podInformer       cache.SharedIndexInformer
	podLister         v1.PodLister
	namespaceInformer cache.SharedIndexInformer
	namespaceLister   v1.NamespaceLister
	queue             workqueue.RateLimitingInterface
	client            kubernetes.Interface
}

func NewKmeshManageController(client kubernetes.Interface, security *kmeshsecurity.SecretManager) (*KmeshManageController, error) {
	nodeName := os.Getenv("NODE_NAME")

	informerFactory := informers.NewSharedInformerFactoryWithOptions(client, 0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fmt.Sprintf("spec.nodeName=%s", nodeName)
		}))
	podInformer := informerFactory.Core().V1().Pods().Informer()
	podLister := informerFactory.Core().V1().Pods().Lister()

	factory := informers.NewSharedInformerFactory(client, 0)
	namespaceInformer := factory.Core().V1().Namespaces().Informer()
	namespaceLister := factory.Core().V1().Namespaces().Lister()

	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Errorf("expected *corev1.Pod but got %T", obj)
				return
			}
			namespace, err := namespaceLister.Get(pod.Namespace)
			if err != nil {
				log.Errorf("failed to get pod namespace %s: %v", pod.Namespace, err)
				return
			}

			if !utils.ShouldEnroll(pod, namespace) {
				// TODO: check if pod has redirection annotation, then handleKmeshManage(nspath, false)
				return
			}

			log.Infof("%s/%s: enable Kmesh manage", pod.GetNamespace(), pod.GetName())
			nspath, _ := ns.GetPodNSpath(pod)
			if err := utils.HandleKmeshManage(nspath, true); err != nil {
				log.Errorf("failed to enable Kmesh manage")
				return
			}
			queue.AddRateLimited(QueueItem{podName: pod.Name, podNs: pod.Namespace, action: ActionAddAnnotation})
			sendCertRequest(security, pod, kmeshsecurity.ADD)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod, okOld := oldObj.(*corev1.Pod)
			newPod, okNew := newObj.(*corev1.Pod)
			if !okOld || !okNew {
				log.Errorf("expected *corev1.Pod but got %T and %T", oldObj, newObj)
				return
			}

			namespace, err := namespaceLister.Get(newPod.Namespace)
			if err != nil {
				log.Errorf("failed to get pod namespace %s: %v", newPod.Namespace, err)
				return
			}
			// enable kmesh manage
			if oldPod.Annotations[constants.KmeshRedirectionAnnotation] != "enabled" && utils.ShouldEnroll(newPod, namespace) {
				log.Infof("%s/%s: enable Kmesh manage", newPod.GetNamespace(), newPod.GetName())
				nspath, _ := ns.GetPodNSpath(newPod)
				if err := utils.HandleKmeshManage(nspath, true); err != nil {
					log.Errorf("failed to enable Kmesh manage")
					return
				}
				queue.AddRateLimited(QueueItem{podName: newPod.Name, podNs: newPod.Namespace, action: ActionAddAnnotation})
				sendCertRequest(security, newPod, kmeshsecurity.ADD)
			}

			// disable kmesh manage
			if oldPod.Annotations[constants.KmeshRedirectionAnnotation] == "enabled" && !utils.ShouldEnroll(newPod, namespace) {
				log.Infof("%s/%s: disable Kmesh manage", newPod.GetNamespace(), newPod.GetName())
				nspath, _ := ns.GetPodNSpath(newPod)
				if err := utils.HandleKmeshManage(nspath, false); err != nil {
					log.Errorf("failed to disable Kmesh manage")
					return
				}
				queue.AddRateLimited(QueueItem{podName: newPod.Name, podNs: newPod.Namespace, action: ActionDeleteAnnotation})
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
			if pod.Annotations[constants.KmeshRedirectionAnnotation] == "enabled" {
				log.Infof("%s/%s: Pod managed by Kmesh is deleted", pod.GetNamespace(), pod.GetName())
				sendCertRequest(security, pod, kmeshsecurity.DELETE)
				// We donot need to do handleKmeshManage for delete, because we may have no change to execute a cmd in pod net ns.
				// And we have done this in kmesh-cni
			}
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to add event handler to podInformer: %v", err)
	}

	return &KmeshManageController{
		informerFactory:   informerFactory,
		podInformer:       podInformer,
		podLister:         podLister,
		factory:           factory,
		namespaceInformer: namespaceInformer,
		namespaceLister:   namespaceLister,
		queue:             queue,
		client:            client,
	}, nil
}

func (c *KmeshManageController) Run(stopChan <-chan struct{}) {
	defer c.queue.ShutDown()
	c.informerFactory.Start(stopChan)
	c.factory.Start(stopChan)
	if !cache.WaitForCacheSync(stopChan, c.podInformer.HasSynced, c.namespaceInformer.HasSynced) {
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

	pod, err := c.podLister.Pods(queueItem.podNs).Get(queueItem.podName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Infof("pod %s/%s has been deleted", queueItem.podNs, queueItem.podName)
			return true
		}
		log.Errorf("failed to get pod %s/%s: %v", queueItem.podNs, queueItem.podName, err)
	}
	if pod != nil {
		// TODO: handle error
		namespace, _ := c.namespaceLister.Get(pod.Namespace)
		if queueItem.action == ActionAddAnnotation && utils.ShouldEnroll(pod, namespace) {
			log.Infof("add annotation for pod %s/%s", pod.Namespace, pod.Name)
			err = addKmeshAnnotation(c.client, pod)
		} else if queueItem.action == ActionDeleteAnnotation && !utils.ShouldEnroll(pod, namespace) {
			log.Infof("delete annotation for pod %s/%s", pod.Namespace, pod.Name)
			err = delKmeshAnnotation(c.client, pod)
		}
	}

	if err != nil {
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
