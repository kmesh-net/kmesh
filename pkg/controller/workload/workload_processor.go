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

package workload

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"

	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/api/v2/workloadapi/security"
	"kmesh.net/kmesh/bpf/kmesh/bpf2go"
	"kmesh.net/kmesh/pkg/auth"
	kmeshbpf "kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/config"
	"kmesh.net/kmesh/pkg/controller/telemetry"
	bpf "kmesh.net/kmesh/pkg/controller/workload/bpfcache"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
	"kmesh.net/kmesh/pkg/nets"
)

const (
	LbPolicyRandom    = 0
	KmeshWaypointPort = 15019 // use this fixed port instead of the HboneMtlsPort in kmesh
)

type Processor struct {
	ack *service_discovery_v3.DeltaDiscoveryRequest
	req *service_discovery_v3.DeltaDiscoveryRequest

	hashName      *HashName
	bpf           *bpf.Cache
	nodeName      string
	WorkloadCache cache.WorkloadCache
	ServiceCache  cache.ServiceCache

	once sync.Once
}

func newProcessor(workloadMap bpf2go.KmeshCgroupSockWorkloadMaps) *Processor {
	return &Processor{
		hashName:      NewHashName(),
		bpf:           bpf.NewCache(workloadMap),
		nodeName:      os.Getenv("NODE_NAME"),
		WorkloadCache: cache.NewWorkloadCache(),
		ServiceCache:  cache.NewServiceCache(),
	}
}

func newDeltaRequest(typeUrl string, names []string, initialResourceVersions map[string]string) *service_discovery_v3.DeltaDiscoveryRequest {
	return &service_discovery_v3.DeltaDiscoveryRequest{
		TypeUrl:                 typeUrl,
		ResourceNamesSubscribe:  names,
		InitialResourceVersions: initialResourceVersions,
		ResponseNonce:           "",
		ErrorDetail:             nil,
		Node:                    config.GetConfig(constants.WorkloadMode).GetNode(),
	}
}

func newAckRequest(rsp *service_discovery_v3.DeltaDiscoveryResponse) *service_discovery_v3.DeltaDiscoveryRequest {
	return &service_discovery_v3.DeltaDiscoveryRequest{
		TypeUrl:                rsp.GetTypeUrl(),
		ResourceNamesSubscribe: []string{},
		ResponseNonce:          rsp.GetNonce(),
		ErrorDetail:            nil,
		Node:                   config.GetConfig(constants.WorkloadMode).GetNode(),
	}
}

func (p *Processor) processWorkloadResponse(rsp *service_discovery_v3.DeltaDiscoveryResponse, rbac *auth.Rbac) {
	var err error

	p.ack = newAckRequest(rsp)
	switch rsp.GetTypeUrl() {
	case AddressType:
		err = p.handleAddressTypeResponse(rsp)
	case AuthorizationType:
		err = p.handleAuthorizationTypeResponse(rsp, rbac)
	default:
		err = fmt.Errorf("unsupported type url %s", rsp.GetTypeUrl())
	}
	if err != nil {
		log.Error(err)
	}
}

func (p *Processor) deletePodFrontendData(uid uint32) error {
	var (
		bk = bpf.BackendKey{}
		bv = bpf.BackendValue{}
		fk = bpf.FrontendKey{}
	)

	bk.BackendUid = uid
	if err := p.bpf.BackendLookup(&bk, &bv); err == nil {
		log.Debugf("Find BackendValue: [%#v]", bv)
		fk.Ip = bv.Ip
		if err = p.bpf.FrontendDelete(&fk); err != nil {
			log.Errorf("FrontendDelete failed: %v", err)
			return err
		}
	}

	return nil
}

func (p *Processor) storePodFrontendData(uid uint32, ip []byte) error {
	var (
		fk = bpf.FrontendKey{}
		fv = bpf.FrontendValue{}
	)

	nets.CopyIpByteFromSlice(&fk.Ip, ip)

	fv.UpstreamId = uid
	if err := p.bpf.FrontendUpdate(&fk, &fv); err != nil {
		log.Errorf("Update frontend map failed, err:%s", err)
		return err
	}

	return nil
}

func (p *Processor) removeWorkloadResource(removedResources []string) error {
	for _, uid := range removedResources {
		wl := p.WorkloadCache.GetWorkloadByUid(uid)
		p.WorkloadCache.DeleteWorkload(uid)
		telemetry.DeleteWorkloadMetric(wl)
		if err := p.removeWorkloadFromBpfMap(uid); err != nil {
			return err
		}
	}
	return nil
}

func (p *Processor) removeWorkloadFromBpfMap(uid string) error {
	var (
		err      error
		bkDelete = bpf.BackendKey{}
	)

	backendUid := p.hashName.Hash(uid)
	// 1. for Pod to Pod access, Pod info stored in frontend map, when Pod offline, we need delete the related records
	if err = p.deletePodFrontendData(backendUid); err != nil {
		log.Errorf("deletePodFrontendData %d failed: %v", backendUid, err)
		return err
	}

	// 2. find all endpoint keys related to this workload
	if eks := p.bpf.GetEndpointKeys(backendUid); len(eks) > 0 {
		err = p.deleteEndpointRecords(backendUid, eks.UnsortedList())
		if err != nil {
			return err
		}
	}

	// 3. delete workload from backend map
	bkDelete.BackendUid = backendUid
	if err = p.bpf.BackendDelete(&bkDelete); err != nil {
		log.Errorf("BackendDelete %d failed: %v", backendUid, err)
		return err
	}

	p.hashName.Delete(uid)
	return nil
}

func (p *Processor) deleteServiceFrontendData(service *workloadapi.Service, id uint32) error {
	var (
		err error
		fk  = bpf.FrontendKey{}
	)

	// If old service exist, use its address
	if service != nil {
		for _, networkAddress := range service.GetAddresses() {
			nets.CopyIpByteFromSlice(&fk.Ip, networkAddress.Address)
			if err = p.bpf.FrontendDelete(&fk); err != nil {
				log.Errorf("delete service %s frontend key %v, err: %v", service.ResourceName(), fk, err)
			}
		}
		return nil
	}

	// Otherwise fall back to iterating over the map, this can only occur on restart
	if fks := p.bpf.FrontendIterFindKey(id); len(fks) != 0 {
		log.Debugf("Find Key Count %d", len(fks))
		for _, fk = range fks {
			log.Debugf("deleteServiceFrontendData Key [%#v]", fk)
			if err = p.bpf.FrontendDelete(&fk); err != nil {
				log.Errorf("FrontendDelete failed: %s", err)
				return err
			}
		}
	}

	return nil
}

func (p *Processor) removeServiceResource(resources []string) error {
	for _, name := range resources {
		telemetry.DeleteServiceMetric(name)
		svc := p.ServiceCache.GetService(name)
		p.ServiceCache.DeleteService(name)
		_ = p.removeServiceResourceFromBpfMap(svc, name)
	}
	return nil
}

func (p *Processor) removeServiceResourceFromBpfMap(svc *workloadapi.Service, name string) error {
	var (
		skDelete = bpf.ServiceKey{}
		svDelete = bpf.ServiceValue{}
	)

	serviceId := p.hashName.Hash(name)
	skDelete.ServiceId = serviceId
	if err := p.bpf.ServiceLookup(&skDelete, &svDelete); err == nil {
		if err = p.deleteServiceFrontendData(svc, serviceId); err != nil {
			log.Errorf("deleteServiceFrontendData for service %s failed: %v", name, err)
		}

		if err = p.bpf.ServiceDelete(&skDelete); err != nil {
			log.Errorf("service map delete %s failed: %v", name, err)
		}

		var i uint32
		for i = 1; i <= svDelete.EndpointCount; i++ {
			ekDelete := bpf.EndpointKey{
				ServiceId:    serviceId,
				BackendIndex: i,
			}
			if err = p.bpf.EndpointDelete(&ekDelete); err != nil {
				log.Errorf("delete [%#v] from endpoint map failed: %s", ekDelete, err)
			}
		}
	}
	p.hashName.Delete(name)
	return nil
}

// addWorkloadToService update service & endpoint bpf map when a workload has new bound services
func (p *Processor) addWorkloadToService(sk *bpf.ServiceKey, sv *bpf.ServiceValue, uid uint32) error {
	var (
		err error
		ek  = bpf.EndpointKey{}
		ev  = bpf.EndpointValue{}
	)

	sv.EndpointCount++
	ek.BackendIndex = sv.EndpointCount
	ek.ServiceId = sk.ServiceId
	ev.BackendUid = uid
	if err = p.bpf.EndpointUpdate(&ek, &ev); err != nil {
		log.Errorf("Update endpoint map failed, err:%s", err)
		return err
	}
	if err = p.bpf.ServiceUpdate(sk, sv); err != nil {
		log.Errorf("Update ServiceUpdate map failed, err:%s", err)
		return err
	}
	return nil
}

// handleWorkloadUnboundServices handles when a workload's belonging services removed
func (p *Processor) handleWorkloadUnboundServices(workload *workloadapi.Workload, unboundedEndpointKeys []bpf.EndpointKey) error {
	workloadUid := p.hashName.Hash(workload.Uid)
	log.Debugf("handleWorkloadUnboundServices %s: %v", workload.ResourceName(), unboundedEndpointKeys)
	err := p.deleteEndpointRecords(workloadUid, unboundedEndpointKeys)
	if err != nil {
		log.Errorf("removeResidualServices delete endpoint failed:%v", err)
	}
	return err
}

// handleWorkloadNewBoundServices handles when a workload's belonging services added
func (p *Processor) handleWorkloadNewBoundServices(workload *workloadapi.Workload, newServices []uint32) error {
	var (
		err error
		sk  = bpf.ServiceKey{}
		sv  = bpf.ServiceValue{}
	)

	if newServices == nil {
		return nil
	}

	log.Debugf("handleWorkloadNewBoundServices %s: %v", workload.ResourceName(), newServices)
	workloadId := p.hashName.Hash(workload.GetUid())
	for _, svcUid := range newServices {
		sk.ServiceId = svcUid
		// the service already stored in map, add endpoint
		if err = p.bpf.ServiceLookup(&sk, &sv); err == nil {
			if err = p.addWorkloadToService(&sk, &sv, workloadId); err != nil {
				log.Errorf("addWorkloadToService workload %d service %d failed: %v", workloadId, sk.ServiceId, err)
				return err
			}
		}
	}
	return nil
}

func (p *Processor) updateWorkload(workload *workloadapi.Workload) error {
	var (
		err         error
		bk          = bpf.BackendKey{}
		bv          = bpf.BackendValue{}
		networkMode = workload.GetNetworkMode()
	)

	uid := p.hashName.Hash(workload.GetUid())

	if waypoint := workload.GetWaypoint(); waypoint != nil {
		nets.CopyIpByteFromSlice(&bv.WaypointAddr, waypoint.GetAddress().Address)
		bv.WaypointPort = nets.ConvertPortToBigEndian(waypoint.GetHboneMtlsPort())
	}

	for serviceName := range workload.GetServices() {
		bv.Services[bv.ServiceCount] = p.hashName.Hash(serviceName)
		bv.ServiceCount++
		if bv.ServiceCount >= bpf.MaxServiceNum {
			log.Warnf("exceed the max service count, currently, a pod can belong to a maximum of 10 services")
			break
		}
	}

	for _, ip := range workload.GetAddresses() {
		bk.BackendUid = uid
		nets.CopyIpByteFromSlice(&bv.Ip, ip)
		if err = p.bpf.BackendUpdate(&bk, &bv); err != nil {
			log.Errorf("Update backend map failed, err:%s", err)
			return err
		}

		// we should not store frontend data of hostname network mode pods
		// please see https://github.com/kmesh-net/kmesh/issues/631
		if networkMode != workloadapi.NetworkMode_HOST_NETWORK {
			if err = p.storePodFrontendData(uid, ip); err != nil {
				log.Errorf("storePodFrontendData failed, err:%s", err)
				return err
			}
		}
	}
	return nil
}

func (p *Processor) handleWorkload(workload *workloadapi.Workload) error {
	log.Debugf("handle workload: %s", workload.Uid)

	p.WorkloadCache.AddOrUpdateWorkload(workload)

	unboundedEndpointKeys, newServices := p.compareWorkloadServices(workload)
	if err := p.handleWorkloadUnboundServices(workload, unboundedEndpointKeys); err != nil {
		log.Errorf("handleWorkloadUnboundServices %s failed: %v", workload.ResourceName(), err)
		return err
	}

	// Add new services associated with the workload
	if err := p.handleWorkloadNewBoundServices(workload, newServices); err != nil {
		log.Errorf("handleWorkloadNewBoundServices %s failed: %v", workload.ResourceName(), err)
		return err
	}

	// update frontend and backend bpf map
	if err := p.updateWorkload(workload); err != nil {
		log.Errorf("updateWorkload %s failed: %v", workload.Uid, err)
		return err
	}

	return nil
}

// compareWorkloadServices compares workload.Services with existing ones and return the unbounded EndpointKeys and new bound services IDs.
func (p *Processor) compareWorkloadServices(workload *workloadapi.Workload) ([]bpf.EndpointKey, []uint32) {
	workloadUid := p.hashName.Hash(workload.Uid)
	allServices := sets.New[uint32]()
	for svcKey := range workload.Services {
		allServices.Insert(p.hashName.Hash(svcKey))
	}
	unboundedEndpointKeys := []bpf.EndpointKey{}
	eks := p.bpf.GetEndpointKeys(workloadUid)
	for ek := range eks {
		if !allServices.Contains(ek.ServiceId) {
			unboundedEndpointKeys = append(unboundedEndpointKeys, ek)
		}
		allServices.Delete(ek.ServiceId)
	}
	newServices := allServices.UnsortedList()
	return unboundedEndpointKeys, newServices
}

func (p *Processor) storeServiceFrontendData(serviceId uint32, service *workloadapi.Service) error {
	var (
		err error
		fk  = bpf.FrontendKey{}
		fv  = bpf.FrontendValue{}
	)

	fv.UpstreamId = serviceId
	for _, networkAddress := range service.GetAddresses() {
		nets.CopyIpByteFromSlice(&fk.Ip, networkAddress.Address)
		if err = p.bpf.FrontendUpdate(&fk, &fv); err != nil {
			log.Errorf("Update Frontend failed, err:%s", err)
			return err
		}
	}
	return nil
}

func (p *Processor) storeServiceData(serviceName string, waypoint *workloadapi.GatewayAddress, ports []*workloadapi.Port) error {
	var (
		err      error
		sk       = bpf.ServiceKey{}
		oldValue = bpf.ServiceValue{}
	)

	sk.ServiceId = p.hashName.Hash(serviceName)

	newValue := bpf.ServiceValue{}
	newValue.LbPolicy = LbPolicyRandom
	if waypoint != nil {
		nets.CopyIpByteFromSlice(&newValue.WaypointAddr, waypoint.GetAddress().Address)
		newValue.WaypointPort = nets.ConvertPortToBigEndian(waypoint.GetHboneMtlsPort())
	}

	for i, port := range ports {
		if i >= bpf.MaxPortNum {
			log.Warnf("exceed the max port count,current only support maximum of 10 ports")
			break
		}

		newValue.ServicePort[i] = nets.ConvertPortToBigEndian(port.ServicePort)
		if strings.Contains(serviceName, "waypoint") {
			newValue.TargetPort[i] = nets.ConvertPortToBigEndian(KmeshWaypointPort)
		} else {
			newValue.TargetPort[i] = nets.ConvertPortToBigEndian(port.TargetPort)
		}
	}

	// Already exists, it means this is service update.
	if err = p.bpf.ServiceLookup(&sk, &oldValue); err == nil {
		newValue.EndpointCount = oldValue.EndpointCount
	}

	if err = p.bpf.ServiceUpdate(&sk, &newValue); err != nil {
		log.Errorf("Update Service failed, err:%s", err)
	}

	return nil
}

func (p *Processor) handleService(service *workloadapi.Service) error {
	log.Debugf("handle service resource: %s", service.ResourceName())

	containsPort := func(port uint32) bool {
		for _, p := range service.GetPorts() {
			if p.GetServicePort() == port {
				return true
			}
		}

		return false
	}

	// Preprocess service, remove the waypoint from waypoint service, otherwise it will fall into a loop in bpf
	if service.Waypoint != nil {
		// Currently istiod only set the waypoint address to the first address of the service
		// When waypoints of different granularities are deployed together, the only waypoint service to be determined
		// is whether it contains port 15021, ref: https://github.com/kmesh-net/kmesh/issues/691
		// TODO: remove when upstream istiod will not set the waypoint address for itself
		if slices.Equal(service.GetWaypoint().GetAddress().Address, service.Addresses[0].Address) || containsPort(15021) {
			service.Waypoint = nil
		}
	}

	p.ServiceCache.AddOrUpdateService(service)
	serviceName := service.ResourceName()
	serviceId := p.hashName.Hash(serviceName)

	// store in frontend
	if err := p.storeServiceFrontendData(serviceId, service); err != nil {
		log.Errorf("storeServiceFrontendData failed, err:%s", err)
		return err
	}

	// get endpoint from ServiceCache, and update service and endpoint map
	if err := p.storeServiceData(serviceName, service.GetWaypoint(), service.GetPorts()); err != nil {
		log.Errorf("storeServiceData failed, err:%s", err)
		return err
	}
	return nil
}

func (p *Processor) handleRemovedAddresses(removed []string) {
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

	if err := p.removeWorkloadResource(workloadNames); err != nil {
		log.Errorf("RemoveWorkloadResource failed: %v", err)
	}
	if err := p.removeServiceResource(serviceNames); err != nil {
		log.Errorf("RemoveServiceResource failed: %v", err)
	}
}

func (p *Processor) handleAddressTypeResponse(rsp *service_discovery_v3.DeltaDiscoveryResponse) error {
	var err error
	// sort resources, first process services, then workload
	var services []*workloadapi.Service
	var workloads []*workloadapi.Workload
	for _, resource := range rsp.GetResources() {
		address := &workloadapi.Address{}
		if err = anypb.UnmarshalTo(resource.Resource, address, proto.UnmarshalOptions{}); err != nil {
			continue
		}

		switch address.GetType().(type) {
		case *workloadapi.Address_Workload:
			workloads = append(workloads, address.GetWorkload())
		case *workloadapi.Address_Service:
			services = append(services, address.GetService())
		default:
			log.Errorf("unknown type")
		}
	}

	for _, service := range services {
		log.Debugf("handle service %v", service.ResourceName())
		if err = p.handleService(service); err != nil {
			log.Errorf("handle service failed, err: %v", err)
		}
	}

	for _, workload := range workloads {
		log.Debugf("handle workload %v", workload.ResourceName())
		if err = p.handleWorkload(workload); err != nil {
			log.Errorf("handle workload failed, err: %v", err)
		}
	}

	p.handleRemovedAddresses(rsp.RemovedResources)
	p.once.Do(p.handleRemovedAddressesDuringRestart)
	return err
}

// After restart, we can get the removed addresses by comparing the
// hash table with the cache. If the address is in the hash table but not in the cache, this is a removed address
// We need to delete these addresses from the bpf map only once after restart.
func (p *Processor) handleRemovedAddressesDuringRestart() {
	var (
		bk = bpf.BackendKey{}
		bv = bpf.BackendValue{}
		sk = bpf.ServiceKey{}
		sv = bpf.ServiceValue{}
	)

	if kmeshbpf.GetStartType() != kmeshbpf.Restart {
		return
	}

	log.Infof("reload workload config from last epoch")
	// We traverse hashName, if there is a record exists in bpf map
	// but not in userspace cache, that means the data in the bpf map load
	// from the last epoch is inconsistent with the data that should
	// actually be stored now. then we should delete it from bpf map
	for str, num := range p.hashName.strToNum {
		if p.WorkloadCache.GetWorkloadByUid(str) == nil && p.ServiceCache.GetService(str) == nil {
			log.Debugf("GetWorkloadByUid and GetService nil:%v", str)

			bk.BackendUid = num
			sk.ServiceId = num
			if err := p.bpf.BackendLookup(&bk, &bv); err == nil {
				log.Debugf("found BackendValue: [%#v] and removeWorkloadFromBpfMap", bv)
				if err := p.removeWorkloadFromBpfMap(str); err != nil {
					log.Errorf("removeWorkloadFromBpfMap failed: %v", err)
				}
			} else if err := p.bpf.ServiceLookup(&sk, &sv); err == nil {
				log.Debugf("found ServiceValue: [%#v] and removeServiceResourceFromBpfMap", sv)
				if err := p.removeServiceResourceFromBpfMap(nil, str); err != nil {
					log.Errorf("removeServiceResourceFromBpfMap failed: %v", err)
				}
			}
		}
	}
}

func (p *Processor) handleAuthorizationTypeResponse(rsp *service_discovery_v3.DeltaDiscoveryResponse, rbac *auth.Rbac) error {
	if rbac == nil {
		return fmt.Errorf("Rbac module uninitialized")
	}
	// update resource
	for _, resource := range rsp.GetResources() {
		auth := &security.Authorization{}
		if err := anypb.UnmarshalTo(resource.Resource, auth, proto.UnmarshalOptions{}); err != nil {
			log.Errorf("unmarshal failed, err: %v", err)
			continue
		}
		log.Debugf("handle authorization policy %s, auth %s", resource.GetName(), auth.String())
		if err := rbac.UpdatePolicy(auth); err != nil {
			return err
		}
	}

	// delete resource by name
	for _, resourceName := range rsp.GetRemovedResources() {
		rbac.RemovePolicy(resourceName)
		log.Debugf("remove authorization policy %s", resourceName)
	}

	return nil
}

// deleteEndpointRecords deletes endpoint from endpoint map and simultaneously update service map
func (p *Processor) deleteEndpointRecords(workloadId uint32, endpointKeys []bpf.EndpointKey) error {
	var (
		sk = bpf.ServiceKey{}
		sv = bpf.ServiceValue{}
	)

	for _, ek := range endpointKeys {
		// 1. find the service
		sk.ServiceId = ek.ServiceId
		if err := p.bpf.ServiceLookup(&sk, &sv); err == nil {
			// 2. find the last indexed endpoint of the service
			if err := p.bpf.EndpointSwap(ek.BackendIndex, sv.EndpointCount, sk.ServiceId); err != nil {
				log.Errorf("swap workload %d endpoint index failed: %s", workloadId, err)
				return err
			}

			sv.EndpointCount = sv.EndpointCount - 1
			if err = p.bpf.ServiceUpdate(&sk, &sv); err != nil {
				log.Errorf("ServiceUpdate failed: %s", err)
				return err
			}
		} else {
			// service not exist, we should also delete the endpoint
			log.Errorf("service %d not found, should not occur: %v", ek.ServiceId, err)
			// delete endpoint from map
			if err := p.bpf.EndpointDelete(&ek); err != nil {
				log.Errorf("EndpointDelete [%#v] failed: %v", ek, err)
				return err
			}
		}
	}
	return nil
}
