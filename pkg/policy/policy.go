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
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/client-go/util/workqueue"
	"path/filepath"
	"time"
)

const (
	pkgSubsys = "policy"
	InformerNameService = "Service"
	InformerNameEndpoints = "Endpoints"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
)

type KubeController struct {
	queue		workqueue.RateLimitingInterface
	factory		informers.SharedInformerFactory
	serviceInformer		informersCoreV1.ServiceInformer
	endpointInformer	informersCoreV1.EndpointsInformer
}

type queueKey struct {
	typ		string
	opt		string
	name	string
}

func NewKubeController(clientset kubernetes.Interface) *KubeController {
	factory := informers.NewSharedInformerFactory(clientset, time.Second * 30)

	c := &KubeController{
		factory: factory,
		serviceInformer: factory.Core().V1().Services(),
		endpointInformer: factory.Core().V1().Endpoints(),
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "KubeController"),
	}

	handler := cache.ResourceEventHandlerFuncs{
		AddFunc: c.enqueueForAdd,
		UpdateFunc: c.enqueueForUpdate,
		DeleteFunc: c.enqueueForDelete,
	}
	c.serviceInformer.Informer().AddEventHandler(handler)
	c.endpointInformer.Informer().AddEventHandler(handler)

	return c
}

func (c *KubeController) getObjectType(obj interface{}) string {
	switch obj.(type) {
	case *apiCoreV1.Service:
		return InformerNameService
	case *apiCoreV1.Endpoints:
		return InformerNameEndpoints
	default:
		return ""
	}
}

func (c *KubeController) checkObjectValidity(oldObj, newObj interface{}) bool {
	if oldObj == newObj {
		return false
	}

	switch newObj.(type) {
	case *apiCoreV1.Service:
		return true
	case *apiCoreV1.Endpoints:
		for _, subset := range newObj.(*apiCoreV1.Endpoints).Subsets {
			for _, addr := range subset.Addresses {
				if addr.IP != "" {
					return true
				}
			}
		}
	default:
	}

	return false
}

func (c *KubeController) enqueue(opt, typ, name string) {
	key := queueKey{
		opt: opt,
		typ: typ,
		name: name,
	}
	c.queue.AddRateLimited(key)
}

func (c *KubeController) enqueueForAdd(obj interface{}) {
	name, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		runtime.HandleError(err)
		return
	}
	c.enqueue("Add", c.getObjectType(obj), name)
}

func (c *KubeController) enqueueForUpdate(oldObj, newObj interface{}) {
	if !c.checkObjectValidity(oldObj, newObj) {
		return
	}

	name, err := cache.MetaNamespaceKeyFunc(newObj)
	if err != nil {
		runtime.HandleError(err)
		return
	}
	c.enqueue("Update", c.getObjectType(newObj), name)
}

func (c *KubeController) enqueueForDelete(obj interface{}) {
	name, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != err {
		runtime.HandleError(err)
		return
	}
	c.enqueue("Delete", c.getObjectType(obj), name)
}

func (c *KubeController) syncHandler(key queueKey) error {
	var (
		err error
		exists bool
		obj interface{}
		serviceObj *apiCoreV1.Service
		endpointsObj *apiCoreV1.Endpoints
	)

	switch key.typ {
	case InformerNameService:
		obj, exists, err = c.serviceInformer.Informer().GetIndexer().GetByKey(key.name)
		if err == nil && exists {
			serviceObj = obj.(*apiCoreV1.Service)
			fmt.Printf("syncHandler for Service: %#v\n", serviceObj)
		}
	case InformerNameEndpoints:
		obj, exists, err = c.endpointInformer.Informer().GetIndexer().GetByKey(key.name)
		if err == nil && exists {
			endpointsObj = obj.(*apiCoreV1.Endpoints)
			fmt.Printf("syncHandler for Endpoints: %#v\n", endpointsObj)
		}
	default:
		return fmt.Errorf("invlid queueKey name")
	}

	if err != nil {
		return fmt.Errorf("get object with key %#v from store failed with %v", key, err)
	}
	if !exists {
		fmt.Printf("Service or Endpoints %#v does not exist anymore\n", key)
		return nil
	}

	return nil
}

func (c *KubeController) processNextWorkItem() bool {
	obj, shutdown := c.queue.Get()
	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer c.queue.Done(obj)

		key, ok := obj.(queueKey)
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

func (c *KubeController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *KubeController) Run(stopCh <-chan struct{}) error {
	defer c.queue.ShutDown()

	go c.factory.Start(stopCh)

	if ok := cache.WaitForCacheSync(stopCh, c.serviceInformer.Informer().HasSynced); !ok {
		return fmt.Errorf("kube wait for caches to sync failed")
	}

	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
	return nil
}

func KubeClient() error {
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

	controller := NewKubeController(clientset)
	if err := controller.Run(stopCh); err != nil {
		return err
	}

	return nil
}

func ControlManager() {
	KubeClient()
}