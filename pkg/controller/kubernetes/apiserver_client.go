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
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"time"
)

const (
	InformerTypeService = "Service"
	InformerTypeEndpoints = "Endpoints"
	InformerTypeNode = "Node"

	InformerOptAdd = "Add"
	InformerOptUpdate = "Update"
	InformerOptDelete = "Delete"
)

type ApiserverClient struct {
	queue            workqueue.RateLimitingInterface
	factory          informers.SharedInformerFactory
	serviceInformer  informersCoreV1.ServiceInformer
	endpointInformer informersCoreV1.EndpointsInformer
	nodeInformer     informersCoreV1.NodeInformer
	svcHandles       map[string]*serviceHandle
}

type queueKey struct {
	name	string
	opt		string
	typ		string
	oldObj	interface{}
}

func getObjectType(obj interface{}) string {
	switch obj.(type) {
	case *apiCoreV1.Service:
		return InformerTypeService
	case *apiCoreV1.Endpoints:
		return InformerTypeEndpoints
	case *apiCoreV1.Node:
		return InformerTypeNode
	default:
		return ""
	}
}

func checkObjectValidity(obj interface{}) bool {
	switch obj.(type) {
	case *apiCoreV1.Node:
		return true
	case *apiCoreV1.Service:
		return true
	case *apiCoreV1.Endpoints:
		// filter out invalid endpoint without IP
		for _, subset := range obj.(*apiCoreV1.Endpoints).Subsets {
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

func (c *ApiserverClient) enqueue(opt string, oldObj, newObj interface{}) {
	obj := newObj
	if obj == nil {
		obj = oldObj
	}

	name, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		runtime.HandleError(err)
		return
	}

	qkey := queueKey{}
	qkey.typ = getObjectType(obj)
	qkey.opt = opt
	qkey.name = name
	qkey.oldObj = oldObj
	c.queue.AddRateLimited(qkey)
}

func (c *ApiserverClient) enqueueForAdd(obj interface{}) {
	c.enqueue(InformerOptAdd, nil, obj)
}

func (c *ApiserverClient) enqueueForUpdate(oldObj, newObj interface{}) {
	if oldObj == newObj {
		return
	}
	if !checkObjectValidity(oldObj) && !checkObjectValidity(newObj) {
		return
	}
	c.enqueue(InformerOptUpdate, oldObj, newObj)
}

func (c *ApiserverClient) enqueueForDelete(obj interface{}) {
	c.enqueue(InformerOptDelete, obj, nil)
}

func NewApiserverClient(clientSet kubernetes.Interface) (*ApiserverClient, error) {
	factory := informers.NewSharedInformerFactory(clientSet, time.Second * 30)

	c := &ApiserverClient{
		factory: factory,
		serviceInformer: factory.Core().V1().Services(),
		endpointInformer: factory.Core().V1().Endpoints(),
		nodeInformer: factory.Core().V1().Nodes(),
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "ApiserverClient"),
	}

	handler := cache.ResourceEventHandlerFuncs{
		AddFunc: c.enqueueForAdd,
		UpdateFunc: c.enqueueForUpdate,
		DeleteFunc: c.enqueueForDelete,
	}
	c.serviceInformer.Informer().AddEventHandler(handler)
	c.endpointInformer.Informer().AddEventHandler(handler)
	c.nodeInformer.Informer().AddEventHandler(handler)

	c.svcHandles = make(map[string]*serviceHandle)
	return c, nil
}

func (c *ApiserverClient) syncHandler(qkey queueKey) error {
	var (
		err error
		newObj interface{}
	)

	if qkey.typ == InformerTypeNode {
		newObj, _, err = c.nodeInformer.Informer().GetIndexer().GetByKey(qkey.name)
		if err != nil {
			return fmt.Errorf("get object with key %#v from store failed with %v", qkey, err)
		}
		nodeHdl.extractNodeData(serviceOptionDeleteFlag, qkey.oldObj)
		nodeHdl.extractNodeData(serviceOptionUpdateFlag, newObj)
		return nil
	}

	svcHdl := c.svcHandles[qkey.name]
	if svcHdl == nil {
		svcHdl = newServiceHandle(qkey.name)
	}

	switch qkey.typ {
	case InformerTypeService:
		newObj, _, err = c.serviceInformer.Informer().GetIndexer().GetByKey(qkey.name)
		if err == nil {
			svcHdl.service = newServiceEvent(qkey.oldObj, newObj)
		}
	case InformerTypeEndpoints:
		newObj, _, err = c.endpointInformer.Informer().GetIndexer().GetByKey(qkey.name)
		if err == nil {
			svcHdl.endpoints = append(svcHdl.endpoints, newEndpointEvent(qkey.oldObj, newObj))
		}
	default:
		return fmt.Errorf("invlid queueKey name")
	}

	if err != nil {
		return fmt.Errorf("get object with key %#v from store failed with %v", qkey, err)
	}

	c.svcHandles[qkey.name] = svcHdl
	return nil
}

// processNextWorkItem will read a single work item off the queue and
// attempt to process it.
func (c *ApiserverClient) processNextWorkItem() error {
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
		defer func() { qkey.oldObj = nil }()

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

func (c *ApiserverClient) runWorker() {
	if c.queue.Len() == 0 {
		return
	}

	// Dequeue until the queue is empty, and then process in batch
	for c.queue.Len() > 0 {
		if err := c.processNextWorkItem(); err != nil {
			log.Error(err)
			break
		}
	}

	// then process in batch
	nodeHdl.batchProcess()
	for name, svcHdl := range c.svcHandles {
		if !svcHdl.isChange() {
			continue
		}
		if svcHdl.service != nil {
			nodeHdl.refreshService(svcHdl.name, svcHdl.service.oldObj, svcHdl.service.newObj)
		}

		svcHdl.batchProcess(nodeHdl.address)
		if svcHdl.isEmpty() {
			svcHdl.destroy()
			delete(c.svcHandles, name)
		}
	}
}

// Run will block until stopCh is closed, at which point it will shutdown the queue
// and wait for workers to finish processing their current work items.
func (c *ApiserverClient) Run(stopCh <-chan struct{}) error {
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

	return nil
}

func (c *ApiserverClient) Close() error {
	*c = ApiserverClient{}
	return nil
}
