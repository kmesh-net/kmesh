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
	"openeuler.io/mesh/pkg/bpf/maps"
)

type objOptionFlag uint

const (
	serviceOptionDeleteFlag objOptionFlag = 0x01
	serviceOptionUpdateFlag objOptionFlag = 0x02
	serviceOptionAllFlag    objOptionFlag = serviceOptionDeleteFlag & serviceOptionUpdateFlag
)

var (
	protocolStrToC = map[apiCoreV1.Protocol]uint32 {
		apiCoreV1.ProtocolTCP: 0, //C.IPPROTO_TCP,
		apiCoreV1.ProtocolUDP: 6, //C.IPPROTO_UDP,
	}

	convert = maps.NewConvertMapKey()
	nodeHdl = newNodeHandle()
)

// k = port
type objCount map[uint32]uint32
type objAddressToMapKey map[maps.Address]maps.MapKey

type serviceHandle struct {
	name		string
	service		*serviceEvent
	endpoints	[]*endpointEvent

	// k = endpointPort, v = count
	serviceCount	objCount
	// k = clusterPort, v = count
	endpointsCount	objCount
	// When you want to delete endpoint from the map,
	// you need to convert the address to key first.
	endpointsAddressToMapKey objAddressToMapKey
}

func newServiceHandle(name string) *serviceHandle {
	handle := &serviceHandle{}
	handle.name = name
	handle.serviceCount = make(objCount)
	handle.endpointsCount = make(objCount)
	handle.endpointsAddressToMapKey = make(objAddressToMapKey)
	return handle
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
	lData := make(listenerData)
	defer func() { lData = nil }()
	cData := make(clusterData)
	defer func() { cData = nil }()
	epData := make(endpointData)
	defer func() { epData = nil }()

	nameID := convert.StrToNum(svc.name)
	for k, epEvent := range svc.endpoints {
		epData.extractData(serviceOptionDeleteFlag, epEvent.oldObj, nameID)
		epData.extractData(serviceOptionUpdateFlag, epEvent.newObj, nameID)

		epEvent.destroy()
		svc.endpoints[k] = nil
	}
	// clear endpoints all elem
	if svc.endpoints != nil {
		svc.endpoints = svc.endpoints[:0]
	}

	if svc.service != nil {
		cData.extractData(serviceOptionDeleteFlag, svc.service.oldObj, nameID)
		cData.extractData(serviceOptionUpdateFlag, svc.service.newObj, nameID)

		lData.extractData(serviceOptionDeleteFlag, svc.service.oldObj, addr, nameID)
		lData.extractData(serviceOptionUpdateFlag, svc.service.newObj, addr, nameID)

		svc.service.destroy()
		svc.service = nil
	}

	// update all map
	epData.flushMap(serviceOptionUpdateFlag, svc.endpointsCount, svc.endpointsAddressToMapKey)
	cData.flushMap(serviceOptionUpdateFlag, svc.serviceCount)
	lData.flushMap(serviceOptionUpdateFlag)

	// delete all map
	lData.flushMap(serviceOptionDeleteFlag)
	cData.flushMap(serviceOptionDeleteFlag, svc.serviceCount)
	epData.flushMap(serviceOptionDeleteFlag, svc.endpointsCount, svc.endpointsAddressToMapKey)
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
type nodeAddress map[string]objOptionFlag

type nodeHandle struct {
	// Mark node changes only
	isChange	bool
	service		nodeService
	address		nodeAddress
}

func newNodeHandle() *nodeHandle {
	handle := &nodeHandle{
		isChange: false,
		service: make(nodeService),
		address: make(nodeAddress),
	}

	return handle
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

func (nd *nodeHandle) extractNodeData(flag objOptionFlag, obj interface{}) {
	if obj == nil {
		return
	}
	node := obj.(*apiCoreV1.Node)

	for _, addr := range node.Status.Addresses {
		// TODO: data.Type == apiCoreV1.NodeExternalIP ???
		if addr.Type != apiCoreV1.NodeInternalIP {
			continue
		}

		nd.isChange = true
		nd.address[addr.Address] |= flag
		if nd.address[addr.Address] == serviceOptionAllFlag {
			nd.address[addr.Address] = 0
		}
	}
}

func (nd *nodeHandle) batchProcess() {
	if !nd.isChange {
		return
	}
	lData := make(listenerData)
	defer func() { lData = nil }()

	for name, svc := range nd.service {
		nameID := convert.StrToNum(name)
		lData.extractData(0, svc, nd.address, nameID)

		lData.flushMap(serviceOptionUpdateFlag)
		lData.flushMap(serviceOptionDeleteFlag)
	}

	for ip, flag := range nd.address {
		if flag == serviceOptionDeleteFlag {
			delete(nd.address, ip)
		} else {
			nd.address[ip] = 0
		}
	}

	nd.isChange = false
}
