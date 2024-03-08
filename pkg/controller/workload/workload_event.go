/*
 * Copyright 2024 The Kmesh Authors.
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

package workload

import (
	"encoding/binary"
	"fmt"
	"strings"

	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	workloadapi "kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/api/v2/workloadapi/security"
	"kmesh.net/kmesh/pkg/auth"
	"kmesh.net/kmesh/pkg/controller/config"
	nets "kmesh.net/kmesh/pkg/nets"
)

const (
	ConverNumBase  = 10
	MaxPortPairNum = 10
	LbPolicyRandom = 0
	RandTimeSed    = 1000
)

var (
	hashName = NewHashName()
)

type ServiceEvent struct {
	ack  *service_discovery_v3.DeltaDiscoveryRequest
	rqt  *service_discovery_v3.DeltaDiscoveryRequest
	rbac *auth.Rbac
}

var (
	ServiceCache map[string]Endpoints = make(map[string]Endpoints)
)

type Endpoints map[string]Endpoint

type Endpoint struct {
	workloadUid string
	serviceName string
	portCount   uint32
	portList    []*workloadapi.Port
}

func NewServiceEvent() *ServiceEvent {
	return &ServiceEvent{
		ack:  nil,
		rqt:  nil,
		rbac: auth.NewRbac(),
	}
}

func (svc *ServiceEvent) Destroy() {
	*svc = ServiceEvent{}
}

func newWorkloadRequest(typeUrl string, names []string) *service_discovery_v3.DeltaDiscoveryRequest {
	return &service_discovery_v3.DeltaDiscoveryRequest{
		TypeUrl:                typeUrl,
		ResourceNamesSubscribe: names,
		ResponseNonce:          "",
		ErrorDetail:            nil,
		Node:                   config.GetConfig().GetNode(),
	}
}

func newAckRequest(rsp *service_discovery_v3.DeltaDiscoveryResponse) *service_discovery_v3.DeltaDiscoveryRequest {
	return &service_discovery_v3.DeltaDiscoveryRequest{
		TypeUrl:                rsp.GetTypeUrl(),
		ResourceNamesSubscribe: []string{},
		ResponseNonce:          rsp.GetNonce(),
		ErrorDetail:            nil,
		Node:                   config.GetConfig().GetNode(),
	}
}

func (svc *ServiceEvent) processWorkloadResponse(rsp *service_discovery_v3.DeltaDiscoveryResponse) {
	var err error

	svc.ack = newAckRequest(rsp)
	if rsp.GetResources() != nil {
		switch rsp.GetTypeUrl() {
		case AddressType:
			err = handleAddressTypeResponse(rsp)
		case AuthorizationType:
			err = svc.handleAuthorizationTypeResponse(rsp)
		default:
			err = fmt.Errorf("unsupport type url %s", rsp.GetTypeUrl())
		}
	}
	if err != nil {
		log.Error(err)
	}
}

func removeWorkloadResource(removed_resources []string) error {
	var (
		err      error
		skUpdate = ServiceKey{}
		svUpdate = ServiceValue{}
		ekUpdate = EndpointKey{}
		evUpdate = EndpointValue{}
		ekDelete = EndpointKey{}
		evDelete = EndpointValue{}
		bkDelete = BackendKey{}
	)

	for _, workloadUid := range removed_resources {
		backendUid := hashName.StrToNum(workloadUid)
		if eks := EndpointIterFindKey(backendUid); len(eks) != 0 {
			for _, ekUpdate = range eks {
				log.Debugf("Find EndpointKey: [%#v]", ekUpdate)
				skUpdate.ServiceId = ekUpdate.ServiceId
				if err = ServiceLookup(&skUpdate, &svUpdate); err == nil {
					log.Debugf("Find ServiceValue: [%#v]", svUpdate)
					ekDelete.ServiceId = skUpdate.ServiceId
					ekDelete.BackendIndex = svUpdate.EndpointCount
					if err = EndpointLookup(&ekDelete, &evDelete); err == nil {
						log.Debugf("Find EndpointValue: [%#v]", evDelete)
						evUpdate.BackendUid = evDelete.BackendUid
						if err = EndpointUpdate(&ekUpdate, &evUpdate); err != nil {
							log.Errorf("EndpointUpdate failed: %s", err)
							goto failed
						}
						if err = EndpointDelete(&ekDelete); err != nil {
							log.Errorf("EndpointDelete failed: %s", err)
							goto failed
						}
						svUpdate.EndpointCount = svUpdate.EndpointCount - 1
						if err = ServiceUpdate(&skUpdate, &svUpdate); err != nil {
							log.Errorf("ServiceUpdate failed: %s", err)
							goto failed
						}
					}
				}
			}
		}
		bkDelete.BackendUid = backendUid
		if err = BackendDelete(&bkDelete); err != nil {
			log.Errorf("BackendDelete failed: %s", err)
			goto failed
		}
		hashName.Delete(workloadUid)
	}

failed:
	return err
}

func deleteFrontendData(id uint32) error {
	var (
		err error
		fk  = FrontendKey{}
	)
	if fks := FrontendIterFindKey(id); len(fks) != 0 {
		log.Debugf("Find Key Count %d", len(fks))
		for _, fk = range fks {
			log.Debugf("deleteFrontendData Key [%#v]", fk)
			if err = FrontendDelete(&fk); err != nil {
				log.Errorf("FrontendDelete failed: %s", err)
				return err
			}
		}
	}

	return nil
}

func removeServiceResource(removed_resources []string) error {
	var (
		err      error
		skDelete = ServiceKey{}
		svDelete = ServiceValue{}
		ekDelete = EndpointKey{}
	)

	for _, name := range removed_resources {
		serviceId := hashName.StrToNum(name)
		skDelete.ServiceId = serviceId
		if err = ServiceLookup(&skDelete, &svDelete); err == nil {
			if err = deleteFrontendData(serviceId); err != nil {
				log.Errorf("deleteFrontendData failed: %s", err)
				goto failed
			}

			if err = ServiceDelete(&skDelete); err != nil {
				log.Errorf("ServiceDelete failed: %s", err)
				goto failed
			}

			var i uint32
			for i = 1; i <= svDelete.EndpointCount; i++ {
				ekDelete.ServiceId = serviceId
				ekDelete.BackendIndex = i
				if err = EndpointDelete(&ekDelete); err != nil {
					log.Errorf("EndpointDelete failed: %s", err)
					goto failed
				}
			}
		}
		hashName.Delete(name)
	}

failed:
	return err
}

func storeEndpointWithService(sk *ServiceKey, sv *ServiceValue, uid uint32) error {
	var (
		err error
		ek  = EndpointKey{}
		ev  = EndpointValue{}
	)
	sv.EndpointCount++
	ek.BackendIndex = sv.EndpointCount
	ek.ServiceId = sk.ServiceId
	ev.BackendUid = uid
	if err = EndpointUpdate(&ek, &ev); err != nil {
		log.Errorf("Update endpoint map failed, err:%s", err)
		return err
	}
	if err = ServiceUpdate(sk, sv); err != nil {
		log.Errorf("Update ServiceUpdate map failed, err:%s", err)
		return err
	}

	return nil
}

func storeServiceCache(workload_uid string, serviceName string, portList *workloadapi.PortList) {
	var endpoint Endpoint
	endpoint.workloadUid = workload_uid
	endpoint.serviceName = serviceName
	endpoint.portCount = uint32(len(portList.Ports))
	endpoint.portList = portList.Ports

	endpointCaches, ok := ServiceCache[serviceName]
	if !ok {
		ServiceCache[serviceName] = make(Endpoints)
		endpointCaches = ServiceCache[serviceName]
	}

	endpointCaches[workload_uid] = endpoint
}

func storeBackendData(uid uint32, ips [][]byte, portList *workloadapi.PortList) error {
	var (
		err error
		bk  = BackendKey{}
		bv  = BackendValue{}
	)

	bk.BackendUid = uid
	for _, ip := range ips {
		bv.IPv4 = binary.LittleEndian.Uint32(ip)
		bv.PortCount = uint32(len(portList.Ports))
		for i, portPair := range portList.Ports {
			if i >= MaxPortPairNum {
				log.Warnf("exceed the max port count")
				break
			}
			bv.ServicePort[i] = nets.ConvertPortToBigEndian(portPair.ServicePort)
			bv.TargetPort[i] = nets.ConvertPortToBigEndian(portPair.TargetPort)
			if err = BackendUpdate(&bk, &bv); err != nil {
				log.Errorf("Update backend map failed, err:%s", err)
				return err
			}
		}
	}
	return nil
}

func handleDataWithService(workload *workloadapi.Workload) error {
	var (
		err error
		sk  = ServiceKey{}
		sv  = ServiceValue{}

		bk = BackendKey{}
		bv = BackendValue{}
	)
	backend_uid := hashName.StrToNum(workload.GetUid())

	for serviceName, portList := range workload.GetServices() {
		bk.BackendUid = backend_uid
		// for update sense, if the backend is exist, just need update it
		if err = BackendLookup(&bk, &bv); err != nil {
			sk.ServiceId = hashName.StrToNum(serviceName)
			// the service already stored in map, add endpoint
			if err = ServiceLookup(&sk, &sv); err == nil {
				if err = storeEndpointWithService(&sk, &sv, backend_uid); err != nil {
					log.Errorf("storeEndpointWithService failed, err:%s", err)
					return err
				}
			} else { // the service has not exist in the map yet, we need store it in the ServiceCache cache
				storeServiceCache(workload.GetUid(), serviceName, portList)
			}
		}
	}

	for _, portList := range workload.GetServices() {
		// store workload info in backend map, after service come, add the endpoint relationship
		ips := workload.GetAddresses()
		if err = storeBackendData(backend_uid, ips, portList); err != nil {
			log.Errorf("storeBackendData failed, err:%s", err)
			return err
		}
	}

	return nil
}

func handleDataWithoutService(workload *workloadapi.Workload) error {
	var (
		err error
		bk  = BackendKey{}
		bv  = BackendValue{}
	)
	bk.BackendUid = hashName.StrToNum(workload.GetUid())
	ips := workload.GetAddresses()
	for _, ip := range ips {
		bv.IPv4 = binary.LittleEndian.Uint32(ip)
		if err = BackendUpdate(&bk, &bv); err != nil {
			log.Errorf("Update backend map failed, err:%s", err)
			return err
		}
	}
	return nil
}

func handleWorkloadData(workload *workloadapi.Workload) error {
	var err error

	// if have the service name, the workload belongs to a service
	if workload.GetServices() != nil {
		if err = handleDataWithService(workload); err != nil {
			log.Errorf("handleDataWithService failed, err:%s", err)
			return err
		}
	} else { // independent workload without service
		if err = handleDataWithoutService(workload); err != nil {
			log.Errorf("handleDataWithoutService failed, err:%s", err)
			return err
		}
	}

	return nil
}

func storeFrontendData(serviceId uint32, service *workloadapi.Service) error {
	var (
		err error
		fk  = FrontendKey{}
		fv  = FrontendValue{}
	)

	fv.ServiceId = serviceId
	for _, networkAddress := range service.GetAddresses() {
		address := networkAddress.Address
		fk.IPv4 = binary.LittleEndian.Uint32(address)
		for _, portPair := range service.GetPorts() {
			fk.Port = nets.ConvertPortToBigEndian(portPair.ServicePort)
			if err = FrontendUpdate(&fk, &fv); err != nil {
				log.Errorf("Update Frontend failed, err:%s", err)
				return err
			}
		}
	}
	return nil
}

func storeServiceData(serviceName string) error {
	var (
		err error
		ek  = EndpointKey{}
		ev  = EndpointValue{}
		sk  = ServiceKey{}
		sv  = ServiceValue{}
	)

	sk.ServiceId = hashName.StrToNum(serviceName)
	sv.LbPolicy = LbPolicyRandom
	sv.EndpointCount = 0 // there are 0 endpoints in the initial state
	endpointCaches, ok := ServiceCache[serviceName]
	if ok {
		for workloadUid, endpoint := range endpointCaches {
			sv.EndpointCount++
			ek.ServiceId = hashName.StrToNum(endpoint.serviceName)
			ek.BackendIndex = sv.EndpointCount
			ev.BackendUid = hashName.StrToNum(workloadUid)

			if err = EndpointUpdate(&ek, &ev); err != nil {
				log.Errorf("Update Endpoint failed, err:%s", err)
				return err
			}
		}
		delete(ServiceCache, serviceName)
	}

	if err = ServiceUpdate(&sk, &sv); err != nil {
		log.Errorf("Update Service failed, err:%s", err)
	}

	return nil
}

func handleServiceData(service *workloadapi.Service) error {
	var (
		err error
		sk  = ServiceKey{}
		sv  = ServiceValue{}
	)

	NamespaceHostname := []string{service.GetNamespace(), service.GetHostname()}
	serviceName := strings.Join(NamespaceHostname, "/")

	serviceId := hashName.StrToNum(serviceName)
	sk.ServiceId = serviceId
	// if service has exist, just need update frontend port info
	if err = ServiceLookup(&sk, &sv); err == nil {
		// update: delete then store
		if err = deleteFrontendData(serviceId); err != nil {
			log.Errorf("deleteFrontendData failed: %s", err)
			return err
		}
		if err = storeFrontendData(serviceId, service); err != nil {
			log.Errorf("storeFrontendData failed, err:%s", err)
			return err
		}
	} else {
		// store in frontend
		if err = storeFrontendData(serviceId, service); err != nil {
			log.Errorf("storeFrontendData failed, err:%s", err)
			return err
		}

		// get endpoint from ServiceCache, and update service and endpoint map
		if err = storeServiceData(serviceName); err != nil {
			log.Errorf("storeServiceData failed, err:%s", err)
			return err
		}
	}
	return nil
}

func handleRemovedAddresses(removed []string) error {
	var workloadNames []string
	var serviceNames []string
	for _, res := range removed {
		// workload resource name format: <cluster>/<group>/<kind>/<namespace>/<name></section-name>
		if strings.Count(res, "/") > 2 {
			workloadNames = append(workloadNames, res)
		} else {
			// service resource name format: namespace/hostname
			serviceNames = append(serviceNames, res)
		}
	}

	if err := removeWorkloadResource(workloadNames); err != nil {
		log.Errorf("RemoveWorkloadResource failed: %v", err)
	}
	if err := removeServiceResource(serviceNames); err != nil {
		log.Errorf("RemoveServiceResource failed: %v", err)
	}

	return nil
}

func handleAddressTypeResponse(rsp *service_discovery_v3.DeltaDiscoveryResponse) error {
	var (
		err     error
		address = &workloadapi.Address{}
	)

	for _, resource := range rsp.GetResources() {
		if err = anypb.UnmarshalTo(resource.Resource, address, proto.UnmarshalOptions{}); err != nil {
			continue
		}

		log.Debugf("resource, %s", resource.Resource)
		switch address.GetType().(type) {
		case *workloadapi.Address_Workload:
			workload := address.GetWorkload()
			log.Debugf("Address_Workload name:%s", workload.Name)
			err = handleWorkloadData(workload)
		case *workloadapi.Address_Service:
			service := address.GetService()
			log.Debugf("Address_Service name:%s", service.Name)
			err = handleServiceData(service)
		default:
			log.Errorf("unknow type")
		}
	}
	if err != nil {
		log.Error(err)
	}

	_ = handleRemovedAddresses(rsp.RemovedResources)

	return err
}

func (svc *ServiceEvent) handleAuthorizationTypeResponse(rsp *service_discovery_v3.DeltaDiscoveryResponse) error {
	// update resource
	for _, resource := range rsp.GetResources() {
		auth := &security.Authorization{}
		if err := anypb.UnmarshalTo(resource.Resource, auth, proto.UnmarshalOptions{}); err != nil {
			log.Errorf("unmarshal failed, err: %v", err)
			continue
		}
		log.Debugf("handle auth xds, resource.name %s, auth %s", resource.GetName(), auth.String())
		if err := svc.rbac.UpdatePolicy(auth); err != nil {
			return err
		}
	}

	// delete resource by name
	for _, rmResourceName := range rsp.GetRemovedResources() {
		svc.rbac.RemovePolicy(rmResourceName)
		log.Debugf("handle rm resource %s", rmResourceName)
	}

	return nil
}
