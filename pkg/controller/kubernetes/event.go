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
	apiCoreV1 "k8s.io/api/core/v1"
	"openeuler.io/mesh/pkg/cache/v1"
)

var (
	hashName = cache_v1.NewHashName()
	nodeHdl = newNodeHandle()
)

type serviceHandle struct {
	name		string
	service		*serviceEvent
	endpoints	[]*endpointEvent

	// k = endpointPort, v = count
	serviceCount	cache_v1.CacheCount
	// k = clusterPort, v = count
	endpointsCount	cache_v1.CacheCount
	// When you want to delete endpoint from the map,
	// you need to convert the address to key first.
	endpointsAddressToMapKey cache_v1.AddressToMapKey
}

func newServiceHandle(name string) *serviceHandle {
	return &serviceHandle{
		name: name,
		serviceCount: make(cache_v1.CacheCount),
		endpointsCount: make(cache_v1.CacheCount),
		endpointsAddressToMapKey: make(cache_v1.AddressToMapKey),
	}
}

func (svc *serviceHandle) destroy() {
	hashName.Delete(svc.name)
	*svc = serviceHandle{}
}

func (svc *serviceHandle) isEmpty() bool {
	for _, c := range svc.serviceCount {
		if c > 0 {
			return false
		}
	}
	for _, c := range svc.endpointsCount {
		if c > 0 {
			return false
		}
	}

	return true
}

func (svc *serviceHandle) isChange() bool {
	if svc.service != nil {
		return true
	}
	if len(svc.endpoints) > 0 {
		return true
	}

	return false
}

func (svc *serviceHandle) batchProcess(addr nodeAddress) {
	lCache := make(cache_v1.ListenerCache)
	defer func() { lCache = nil }()
	cCache := make(cache_v1.ClusterCache)
	defer func() { cCache = nil }()
	epCache := make(cache_v1.EndpointCache)
	defer func() { epCache = nil }()

	nameID := hashName.StrToNum(svc.name)
	for k, epEvent := range svc.endpoints {
		extractEndpointCache(epCache, cache_v1.CacheFlagDelete, nameID, epEvent.oldObj)
		extractEndpointCache(epCache, cache_v1.CacheFlagUpdate, nameID, epEvent.newObj)

		epEvent.destroy()
		svc.endpoints[k] = nil
	}
	// clear endpoints all elem
	if svc.endpoints != nil {
		svc.endpoints = svc.endpoints[:0]
	}

	if svc.service != nil {
		extractClusterCache(cCache, cache_v1.CacheFlagDelete, nameID, svc.service.oldObj)
		extractClusterCache(cCache, cache_v1.CacheFlagUpdate, nameID, svc.service.newObj)

		extractListenerCache(lCache, cache_v1.CacheFlagDelete, nameID, svc.service.oldObj, addr)
		extractListenerCache(lCache, cache_v1.CacheFlagUpdate, nameID, svc.service.newObj, addr)

		svc.service.destroy()
		svc.service = nil
	}

	// update all map
	epCache.Flush(cache_v1.CacheFlagUpdate, svc.endpointsCount, svc.endpointsAddressToMapKey)
	cCache.Flush(cache_v1.CacheFlagUpdate, svc.serviceCount)
	lCache.Flush(cache_v1.CacheFlagUpdate)

	// delete all map
	lCache.Flush(cache_v1.CacheFlagDelete)
	cCache.Flush(cache_v1.CacheFlagDelete, svc.serviceCount)
	epCache.Flush(cache_v1.CacheFlagDelete, svc.endpointsCount, svc.endpointsAddressToMapKey)
}

type endpointEvent struct {
	oldObj	*apiCoreV1.Endpoints
	newObj	*apiCoreV1.Endpoints
}

func newEndpointEvent(oldObj, newObj interface{}) *endpointEvent {
	event := &endpointEvent{}

	if oldObj == nil && newObj == nil {
		return nil
	}

	if oldObj != nil {
		event.oldObj = oldObj.(*apiCoreV1.Endpoints)
	}
	if newObj != nil {
		event.newObj = newObj.(*apiCoreV1.Endpoints)
	}

	return event
}

func (event *endpointEvent) destroy() {
	*event = endpointEvent{}
}

type serviceEvent struct {
	oldObj		*apiCoreV1.Service
	newObj		*apiCoreV1.Service
}

func newServiceEvent(oldObj, newObj interface{}) *serviceEvent {
	event := &serviceEvent{}

	if oldObj == nil && newObj == nil {
		return nil
	}

	if oldObj != nil {
		event.oldObj = oldObj.(*apiCoreV1.Service)
	}
	if newObj != nil {
		event.newObj = newObj.(*apiCoreV1.Service)
	}

	return event
}

func (event *serviceEvent) destroy() {
	*event = serviceEvent{}
}

// k = name
type nodeService map[string]*apiCoreV1.Service
// k = ip
type nodeAddress map[string]cache_v1.CacheOptionFlag

type nodeHandle struct {
	// Mark node changes only
	isChange	bool
	service		nodeService
	address		nodeAddress
}

func newNodeHandle() *nodeHandle {
	return &nodeHandle{
		isChange: false,
		service: make(nodeService),
		address: make(nodeAddress),
	}
}

func (nd *nodeHandle) destroy() {
	nd.service = nil
	nd.address = nil
}

func (nd *nodeHandle) refreshService(name string, oldObj, newObj *apiCoreV1.Service) {
	if oldObj != nil && newObj == nil {
		delete(nd.service, name)
	} else if newObj != nil {
		// TODO: handle other type
		if newObj.Spec.Type == apiCoreV1.ServiceTypeNodePort {
			nd.service[name] = newObj
		}
	}
}

func (nd *nodeHandle) extractNodeCache(flag cache_v1.CacheOptionFlag, obj interface{}) {
	if obj == nil {
		return
	}
	node := obj.(*apiCoreV1.Node)

	for _, addr := range node.Status.Addresses {
		// TODO: Type == apiCoreV1.NodeExternalIP ???
		if addr.Type != apiCoreV1.NodeInternalIP {
			continue
		}

		nd.isChange = true
		nd.address[addr.Address] |= flag
		if nd.address[addr.Address] == cache_v1.CacheFlagAll {
			nd.address[addr.Address] = 0
		}
	}
}

func (nd *nodeHandle) batchProcess() {
	if !nd.isChange {
		return
	}
	lCache := make(cache_v1.ListenerCache)
	defer func() { lCache = nil }()

	for name, svc := range nd.service {
		nameID := hashName.StrToNum(name)
		extractListenerCache(lCache, cache_v1.CacheFlagNone, nameID, svc, nd.address)

		lCache.Flush(cache_v1.CacheFlagUpdate)
		lCache.Flush(cache_v1.CacheFlagDelete)
	}

	for ip, flag := range nd.address {
		if flag == cache_v1.CacheFlagDelete {
			delete(nd.address, ip)
		} else {
			nd.address[ip] = cache_v1.CacheFlagNone
		}
	}

	nd.isChange = false
}
