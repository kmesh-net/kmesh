/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2021-10-09
 */

package kubernetes

import (
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
	"openeuler.io/mesh/pkg/logger"
	"openeuler.io/mesh/pkg/option"
	"path/filepath"
	"time"
)

const (
	pkgSubsys = "apiserver"
	InformerNameService = "Service"
	InformerNameEndpoints = "Endpoints"
	InformerNameNode = "Node"
	InformerOptAdd = "Add"
	InformerOptUpdate = "Update"
	InformerOptDelete = "Delete"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
)

type KubeController struct {
	queue		workqueue.RateLimitingInterface
	factory		informers.SharedInformerFactory
	serviceInformer		informersCoreV1.ServiceInformer
	endpointInformer	informersCoreV1.EndpointsInformer
	nodeInformer		informersCoreV1.NodeInformer
	eventMap	map[EventKey]ClientEvent
}

type queueKey struct {
	typ		string
	EventKey
}

func NewKubeController(clientset kubernetes.Interface) *KubeController {
	factory := informers.NewSharedInformerFactory(clientset, time.Second * 30)

	c := &KubeController{
		factory: factory,
		serviceInformer: factory.Core().V1().Services(),
		endpointInformer: factory.Core().V1().Endpoints(),
		nodeInformer: factory.Core().V1().Nodes(),
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "KubeController"),
	}

	handler := cache.ResourceEventHandlerFuncs{
		AddFunc: c.enqueueForAdd,
		UpdateFunc: c.enqueueForUpdate,
		DeleteFunc: c.enqueueForDelete,
	}
	c.serviceInformer.Informer().AddEventHandler(handler)
	c.endpointInformer.Informer().AddEventHandler(handler)
	c.nodeInformer.Informer().AddEventHandler(handler)

	c.eventMap = make(map[EventKey]ClientEvent)
	return c
}

func (c *KubeController) getObjectType(obj interface{}) string {
	switch obj.(type) {
	case *apiCoreV1.Service:
		return InformerNameService
	case *apiCoreV1.Endpoints:
		return InformerNameEndpoints
	case *apiCoreV1.Node:
		return InformerNameNode
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

func (c *KubeController) enqueue(opt string, obj interface{}) {
	name, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		runtime.HandleError(err)
		return
	}

	qkey := queueKey{}
	qkey.typ = c.getObjectType(obj)
	qkey.opt = opt
	qkey.name = name
	c.queue.AddRateLimited(qkey)
}

func (c *KubeController) enqueueForAdd(obj interface{}) {
	c.enqueue(InformerOptAdd, obj)
}

func (c *KubeController) enqueueForUpdate(oldObj, newObj interface{}) {
	if !c.checkObjectValidity(oldObj, newObj) {
		return
	}
	c.enqueue(InformerOptUpdate, newObj)
}

func (c *KubeController) enqueueForDelete(obj interface{}) {
	c.enqueue(InformerOptDelete, obj)
}

func (c *KubeController) syncHandler(qkey queueKey) error {
	var (
		err error
		exists bool
		obj interface{}
	)
	event := c.eventMap[qkey.EventKey]
	event.Key = qkey.EventKey

	switch qkey.typ {
	case InformerNameService:
		obj, exists, err = c.serviceInformer.Informer().GetIndexer().GetByKey(qkey.name)
		if err == nil {
			event.Service = obj.(*apiCoreV1.Service)
		}
	case InformerNameEndpoints:
		obj, exists, err = c.endpointInformer.Informer().GetIndexer().GetByKey(qkey.name)
		if err == nil {
			event.Endpoints = append(event.Endpoints, obj.(*apiCoreV1.Endpoints))
		}
	case InformerNameNode:
		obj, exists, err = c.nodeInformer.Informer().GetIndexer().GetByKey(qkey.name)
		if err == nil {
			if !exists {
				delete(nodesMap, qkey.name)
			} else {
				nodesMap[qkey.name] = obj.(*apiCoreV1.Node)
			}
		}
	default:
		return fmt.Errorf("invlid queueKey name")
	}

	if err != nil {
		return fmt.Errorf("get object with key %#v from store failed with %v", qkey, err)
	}
	if !exists {
		log.Debugf("Service or Endpoints %#v does not exist anymore", qkey)
	}

	c.eventMap[qkey.EventKey] = event
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

		qkey, ok := obj.(queueKey)
		if !ok {
			c.queue.Forget(obj)
			return fmt.Errorf("queue get unknown obj, %#v", obj)
		}

		if err := c.syncHandler(qkey); err != nil {
			return fmt.Errorf("sync failed, %s %s", qkey, err)
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

		// Dequeue until the queue is empty, and then process in batch
		if c.queue.Len() > 0 {
			continue
		}
		for k, v := range c.eventMap {
			if err := v.EventHandler(); err != nil {
				log.Error(err)
			}
			if v.Empty() {
				delete(c.eventMap, k)
			} else {
				v.Reset()
			}
		}
	}
}

// Run will block until stopCh is closed, at which point it will shutdown the queue
// and wait for workers to finish processing their current work items.
func (c *KubeController) Run(stopCh <-chan struct{}) error {
	defer c.queue.ShutDown()

	go c.factory.Start(stopCh)

	if ok := cache.WaitForCacheSync(stopCh, c.serviceInformer.Informer().HasSynced); !ok {
		return fmt.Errorf("kube wait for service caches to sync failed")
	}
	if ok := cache.WaitForCacheSync(stopCh, c.endpointInformer.Informer().HasSynced); !ok {
		return fmt.Errorf("kube wait for endpoint caches to sync failed")
	}
	if ok := cache.WaitForCacheSync(stopCh, c.nodeInformer.Informer().HasSynced); !ok {
		return fmt.Errorf("kube wait for node caches to sync failed")
	}

	// until stop channel is closed, and running Worker every second
	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
	return nil
}

func Run() error {
	var (
		err error
		config *restclient.Config
	)
	cfg := option.GetClientConfig()

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
