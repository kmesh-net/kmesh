/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description:
 */

package kubernetes

import (
	"openeuler.io/mesh/pkg/logger"
	"openeuler.io/mesh/pkg/option"
	"fmt"
	apiCoreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	informersCoreV1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/client-go/util/workqueue"
	"path/filepath"
	"time"
)

const (
	pkgSubsys = "apiserver"
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
		// filter out invalid endpoint without IP
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
			log.Debugf("syncHandler for Service: %#v", serviceObj)
			fmt.Println("")
		}
		// TODO
	case InformerNameEndpoints:
		obj, exists, err = c.endpointInformer.Informer().GetIndexer().GetByKey(key.name)
		if err == nil && exists {
			endpointsObj = obj.(*apiCoreV1.Endpoints)
			log.Debugf("syncHandler for Endpoints: %#v", endpointsObj)
			fmt.Println("")
		}
		// TODO
	default:
		return fmt.Errorf("invlid queueKey name")
	}

	if err != nil {
		return fmt.Errorf("get object with key %#v from store failed with %v", key, err)
	}
	if !exists {
		log.Debugf("Service or Endpoints %#v does not exist anymore", key)
	}

	return nil
}

// processNextWorkItem will read a single work item off the queue and
// attempt to process it.
func (c *KubeController) processNextWorkItem() error {
	obj, shutdown := c.queue.Get()
	if shutdown {
		return fmt.Errorf("queue alreay shutdown")
	}

	// func for defer queue.Done
	err := func(obj interface{}) error {
		// Let queue knows we have finished processing this item.
		// We also must call Forget if we do not want this work item being re-queued.
		defer c.queue.Done(obj)

		key, ok := obj.(queueKey)
		if !ok {
			c.queue.Forget(obj)
			return fmt.Errorf("queue get unknown obj, %#v", obj)
		}

		if err := c.syncHandler(key); err != nil {
			return fmt.Errorf("sync failed, %s %s", key, err)
		}

		c.queue.Forget(obj)
		return nil
	}(obj)

	if err != nil {
		return err
	}
	return nil
}

func (c *KubeController) runWorker() {
	for true {
		if err := c.processNextWorkItem(); err != nil {
			log.Error(err)
			break
		}
	}
}

// Run will block until stopCh is closed, at which point it will shutdown the queue
// and wait for workers to finish processing their current work items.
func (c *KubeController) Run(stopCh <-chan struct{}) error {
	defer c.queue.ShutDown()

	go c.factory.Start(stopCh)

	if ok := cache.WaitForCacheSync(stopCh, c.serviceInformer.Informer().HasSynced); !ok {
		return fmt.Errorf("kube wait for caches to sync failed")
	}

	// until stop channel is closed, and running Worker every second
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
	return nil
}

func Run(cfg *option.ClientConfig) error {
	var (
		err error
		config *restclient.Config
	)

	if cfg.KubeInCluster {
		config, err = restclient.InClusterConfig()
		if err != nil {
			return fmt.Errorf("kube build config in cluster failed, %s", err)
		}
	} else {
		home := homedir.HomeDir()
		if home == "" {
			return fmt.Errorf("kube get homedir failed")
		}
		kubeconfig := filepath.Join(home, ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return fmt.Errorf("kube build config failed, %s", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("kube new clientset failed, %s", err)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	controller := NewKubeController(clientset)
	if err := controller.Run(stopCh); err != nil {
		return fmt.Errorf("kube run controller failed, %s", err)
	}

	return nil
}
