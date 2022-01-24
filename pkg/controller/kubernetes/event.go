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
	"openeuler.io/mesh/pkg/api"
)

var (
	convert = api.NewConvertName()
	nodeHdl = newNodeHandle()
)

type serviceHandle struct {
	name		string
	service		*serviceEvent
	endpoints	[]*endpointEvent

	// k = endpointPort, v = count
	serviceCount	api.CacheCount
	// k = clusterPort, v = count
	endpointsCount	api.CacheCount
	// When you want to delete endpoint from the map,
	// you need to convert the address to key first.
	endpointsAddressToMapKey api.AddressToMapKey
}

func newServiceHandle(name string) *serviceHandle {
	return &serviceHandle{
		name: name,
		serviceCount: make(api.CacheCount),
		endpointsCount: make(api.CacheCount),
		endpointsAddressToMapKey: make(api.AddressToMapKey),
	}
}

func (svc *serviceHandle) destroy() {
	convert.Delete(svc.name)
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
	lCache := make(api.ListenerCache)
	defer func() { lCache = nil }()
	cCache := make(api.ClusterCache)
	defer func() { cCache = nil }()
	epCache := make(api.EndpointCache)
	defer func() { epCache = nil }()

	nameID := convert.StrToNum(svc.name)
	for k, epEvent := range svc.endpoints {
		extractEndpointCache(epCache, api.CacheFlagDelete, nameID, epEvent.oldObj)
		extractEndpointCache(epCache, api.CacheFlagUpdate, nameID, epEvent.newObj)

		epEvent.destroy()
		svc.endpoints[k] = nil
	}
	// clear endpoints all elem
	if svc.endpoints != nil {
		svc.endpoints = svc.endpoints[:0]
	}

	if svc.service != nil {
		extractClusterCache(cCache, api.CacheFlagDelete, nameID, svc.service.oldObj)
		extractClusterCache(cCache, api.CacheFlagUpdate, nameID, svc.service.newObj)

		extractListenerCache(lCache, api.CacheFlagDelete, nameID, svc.service.oldObj, addr)
		extractListenerCache(lCache, api.CacheFlagUpdate, nameID, svc.service.newObj, addr)

		svc.service.destroy()
		svc.service = nil
	}

	// update all map
	epCache.Flush(api.CacheFlagUpdate, svc.endpointsCount, svc.endpointsAddressToMapKey)
	cCache.Flush(api.CacheFlagUpdate, svc.serviceCount)
	lCache.Flush(api.CacheFlagUpdate)

	// delete all map
	lCache.Flush(api.CacheFlagDelete)
	cCache.Flush(api.CacheFlagDelete, svc.serviceCount)
	epCache.Flush(api.CacheFlagDelete, svc.endpointsCount, svc.endpointsAddressToMapKey)
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
type nodeAddress map[string]api.CacheOptionFlag

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

func (nd *nodeHandle) extractNodeCache(flag api.CacheOptionFlag, obj interface{}) {
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
		if nd.address[addr.Address] == api.CacheFlagAll {
			nd.address[addr.Address] = 0
		}
	}
}

func (nd *nodeHandle) batchProcess() {
	if !nd.isChange {
		return
	}
	lCache := make(api.ListenerCache)
	defer func() { lCache = nil }()

	for name, svc := range nd.service {
		nameID := convert.StrToNum(name)
		extractListenerCache(lCache, api.CacheFlagNone, nameID, svc, nd.address)

		lCache.Flush(api.CacheFlagUpdate)
		lCache.Flush(api.CacheFlagDelete)
	}

	for ip, flag := range nd.address {
		if flag == api.CacheFlagDelete {
			delete(nd.address, ip)
		} else {
			nd.address[ip] = api.CacheFlagNone
		}
	}

	nd.isChange = false
}
