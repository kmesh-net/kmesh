/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description:
 */

package policy

import (
	"codehub.com/mesh/pkg/logger"
	"fmt"
	apiCoreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	informersCoreV1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	listerCoreV1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/client-go/util/workqueue"
	"path/filepath"
	"time"
)

const (
	pkgSubsys = "policy"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
)

type KubeContorller struct {
	factory informers.SharedInformerFactory
	serviceInformer informersCoreV1.ServiceInformer
	endpointInformer informersCoreV1.EndpointsInformer
	serviceLister listerCoreV1.ServiceLister
	endpointLister listerCoreV1.EndpointsLister
	queue workqueue.RateLimitingInterface
}

func NewKubeContorller(clientset kubernetes.Interface) *KubeContorller {
	factory := informers.NewSharedInformerFactory(clientset, time.Second * 30)

	contorller := &KubeContorller{
		factory: factory,
		serviceInformer: factory.Core().V1().Services(),
		endpointInformer: factory.Core().V1().Endpoints(),
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Services"),
	}

	//contorller.serviceInformer.Lister()
	contorller.serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: contorller.enqueue,
		UpdateFunc: contorller.enqueueForUpdate,
		DeleteFunc: contorller.enqueueForDelete,
	})

	return contorller
}

func (c *KubeContorller) syncHandler(key string) error {
	obj, exists, err := c.serviceInformer.Informer().GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("get object with key %s from store failed with %v", key, err)
	}

	if !exists {
		fmt.Printf("Service %s does not exist anymore\n", key)
	} else {
		fmt.Printf("Sync/Add/Update for service: %s\n", obj.(*apiCoreV1.Service).GetName())
		fmt.Printf("Sync/Add/Update for service: %s\n", obj.(*apiCoreV1.Service))
	}

	return nil
}

func (c *KubeContorller) processNextWorkItem() bool {
	obj, shutdown := c.queue.Get()
	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer c.queue.Done(obj)

		key, ok := obj.(string)
		if !ok {
			c.queue.Forget(obj)
			return fmt.Errorf("expected string in queue but got %#v", obj)
		}

		if err := c.syncHandler(key); err != nil {
			return fmt.Errorf("sync failed %s: %s", key, err.Error())
		}

		c.queue.Forget(obj)
		return nil
	}(obj)

	if err != nil {
		log.Debug(err)
		return false
	}

	return true
}

func (c *KubeContorller) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *KubeContorller) Run(stopCh <-chan struct{}) error {
	defer c.queue.ShutDown()

	go c.factory.Start(stopCh)

	if ok := cache.WaitForCacheSync(stopCh, c.serviceInformer.Informer().HasSynced); !ok {
		return fmt.Errorf("kube wait for caches to sync failed")
	}

	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
	return nil
}

func (c *KubeContorller) enqueue(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		runtime.HandleError(err)
		return
	}
	c.queue.AddRateLimited(key)
}

func (c *KubeContorller) enqueueForUpdate(oldObj, newObj interface{}) {
	oldSer := oldObj.(*apiCoreV1.Service)
	newSer := newObj.(*apiCoreV1.Service)
	if oldSer == newSer {
		return
	}
	c.enqueue(newObj)
}

func (c *KubeContorller) enqueueForDelete(obj interface{}) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != err {
		runtime.HandleError(err)
		return
	}
	c.queue.AddRateLimited(key)
}

func kubeClient() error {
	home := homedir.HomeDir()
	if home == "" {
		return fmt.Errorf("kube get home failed")
	}
	kubeconfig := filepath.Join(home, ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("kube build config failed")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("kube now clientset failld")
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	contorller := NewKubeContorller(clientset)
	if err := contorller.Run(stopCh); err != nil {
		return err
	}

	return nil
}

func ControlManager() {
	kubeClient()
}