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
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"

	service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/sets"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/api/v2/workloadapi/security"
	security_v2 "kmesh.net/kmesh/api/v2/workloadapi/security"
	bpf2go "kmesh.net/kmesh/bpf/kmesh/bpf2go/dualengine"
	"kmesh.net/kmesh/pkg/auth"
	kmeshbpf "kmesh.net/kmesh/pkg/bpf/restart"
	maps_v2 "kmesh.net/kmesh/pkg/cache/v2/maps"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/config"
	"kmesh.net/kmesh/pkg/controller/telemetry"
	"kmesh.net/kmesh/pkg/controller/workload/bpfcache"
	bpf "kmesh.net/kmesh/pkg/controller/workload/bpfcache"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
	"kmesh.net/kmesh/pkg/nets"
	"kmesh.net/kmesh/pkg/utils"
)

const (
	KmeshWaypointPort = 15019 // use this fixed port instead of the HboneMtlsPort in kmesh
)

type Processor struct {
	ack *service_discovery_v3.DeltaDiscoveryRequest
	req *service_discovery_v3.DeltaDiscoveryRequest

	hashName      *utils.HashName
	bpf           *bpf.Cache
	nodeName      string
	WorkloadCache cache.WorkloadCache
	ServiceCache  cache.ServiceCache
	EndpointCache cache.EndpointCache
	WaypointCache cache.WaypointCache
	locality      bpf.LocalityCache

	once      sync.Once
	authzOnce sync.Once

	// used to notify Rbac the address/authz type response is done when Kmesh restart
	addressDone     chan struct{}
	authzDone       chan struct{}
	addressRespOnce sync.Once
	authzRespOnce   sync.Once
}

func NewProcessor(workloadMap bpf2go.KmeshCgroupSockWorkloadMaps) *Processor {
	serviceCache := cache.NewServiceCache()

	return &Processor{
		hashName:      utils.NewHashName(),
		bpf:           bpf.NewCache(workloadMap),
		nodeName:      os.Getenv("NODE_NAME"),
		WorkloadCache: cache.NewWorkloadCache(),
		ServiceCache:  serviceCache,
		EndpointCache: cache.NewEndpointCache(),
		WaypointCache: cache.NewWaypointCache(serviceCache),
		locality:      bpf.NewLocalityCache(),
		addressDone:   make(chan struct{}, 1),
		authzDone:     make(chan struct{}, 1),
	}
}

func newDeltaRequest(typeUrl string, names []string, initialResourceVersions map[string]string) *service_discovery_v3.DeltaDiscoveryRequest {
	return &service_discovery_v3.DeltaDiscoveryRequest{
		TypeUrl:                 typeUrl,
		ResourceNamesSubscribe:  names,
		InitialResourceVersions: initialResourceVersions,
		ResponseNonce:           "",
		ErrorDetail:             nil,
		Node:                    config.GetConfig(constants.DualEngineMode).GetNode(),
	}
}

func newAckRequest(rsp *service_discovery_v3.DeltaDiscoveryResponse) *service_discovery_v3.DeltaDiscoveryRequest {
	return &service_discovery_v3.DeltaDiscoveryRequest{
		TypeUrl:                rsp.GetTypeUrl(),
		ResourceNamesSubscribe: []string{},
		ResponseNonce:          rsp.GetNonce(),
		ErrorDetail:            nil,
		Node:                   config.GetConfig(constants.DualEngineMode).GetNode(),
	}
}

func (p *Processor) GetBpfCache() *bpf.Cache {
	return p.bpf
}

func (p *Processor) GetHashName() *utils.HashName {
	return p.hashName
}

func (p *Processor) processWorkloadResponse(rsp *service_discovery_v3.DeltaDiscoveryResponse, rbac *auth.Rbac) {
	var err error

	p.ack = newAckRequest(rsp)
	switch rsp.GetTypeUrl() {
	case AddressType:
		err = p.handleAddressTypeResponse(rsp)
		p.addressRespOnce.Do(func() {
			p.addressDone <- struct{}{}
		})
	case AuthorizationType:
		err = p.handleAuthorizationTypeResponse(rsp, rbac)
		p.authzRespOnce.Do(func() {
			p.authzDone <- struct{}{}
		})
	default:
		err = fmt.Errorf("unsupported type url %s", rsp.GetTypeUrl())
	}
	if err != nil {
		log.Error(err)
	}
}

// TODO: optimize me by passing workload ip directly
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
		return fmt.Errorf("Update frontend map failed, err:%s", err)
	}

	return nil
}

func (p *Processor) removeWorkloadResources(removedResources []string) error {
	for _, uid := range removedResources {
		err := p.removeWorkload(uid)
		if err != nil {
			log.Warnf("removeWorkload %s failed: %v", uid, err)
			continue
		}
	}
	return nil
}

func (p *Processor) removeWorkload(uid string) error {
	p.WaypointCache.DeleteWorkload(uid)
	wl := p.WorkloadCache.GetWorkloadByUid(uid)
	if wl == nil {
		return nil
	}
	p.WorkloadCache.DeleteWorkload(uid)
	telemetry.DeleteWorkloadMetric(wl)
	return p.removeWorkloadFromBpfMap(wl)
}

func (p *Processor) removeWorkloadFromBpfMap(workload *workloadapi.Workload) error {
	var (
		err      error
		bkDelete = bpf.BackendKey{}
	)

	backendUid := p.hashName.Hash(workload.Uid)
	// 1. for Pod to Pod access, Pod info stored in frontend map, when Pod offline, we need delete the related records
	if err = p.deletePodFrontendData(backendUid); err != nil {
		log.Errorf("deletePodFrontendData %d failed: %v", backendUid, err)
		return err
	}

	// 2. find all endpoint keys related to this workload
	if eks := p.bpf.GetEndpointKeys(backendUid); len(eks) > 0 {
		err = p.deleteEndpointRecords(eks.UnsortedList())
		if err != nil {
			return err
		}
	}

	// 3. delete workload from backend map
	bkDelete.BackendUid = backendUid
	if err = p.bpf.BackendDelete(&bkDelete); err != nil {
		return err
	}

	// 4. delete auth policy of workload
	if workload.Node == p.nodeName {
		p.deleteWorkloadPolicies(backendUid)
	}

	p.hashName.Delete(workload.Uid)
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

func (p *Processor) removeServiceResources(resources []string) error {
	for _, name := range resources {
		p.WaypointCache.DeleteService(name)
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
		for j := 0; j < bpf.PrioCount; j++ {
			if svDelete.EndpointCount[j] == 0 {
				continue
			}
			for i = 1; i <= svDelete.EndpointCount[j]; i++ {
				ekDelete := bpf.EndpointKey{
					ServiceId:    serviceId,
					Prio:         uint32(j),
					BackendIndex: i,
				}
				if err = p.bpf.EndpointDelete(&ekDelete); err != nil {
					log.Errorf("delete [%#v] from endpoint map failed: %s", ekDelete, err)
				}
			}
		}
	}
	p.EndpointCache.DeleteEndpointByServiceId(serviceId)
	p.hashName.Delete(name)
	return nil
}

// addWorkloadToService update service & endpoint bpf map when a workload has new bound services
func (p *Processor) addWorkloadToService(sk *bpf.ServiceKey, sv *bpf.ServiceValue, workloadUid uint32, priority uint32) (error, bpf.EndpointKey) {
	var (
		ek = bpf.EndpointKey{}
		ev = bpf.EndpointValue{}
	)

	sv.EndpointCount[priority]++
	ek.BackendIndex = sv.EndpointCount[priority]
	ek.ServiceId = sk.ServiceId
	ek.Prio = priority
	ev.BackendUid = workloadUid
	if err := p.bpf.EndpointUpdate(&ek, &ev); err != nil {
		log.Errorf("Update endpoint map failed, err:%s", err)
		return err, ek
	}
	p.EndpointCache.AddEndpointToService(cache.Endpoint{ServiceId: ek.ServiceId, Prio: ek.Prio, BackendIndex: ek.BackendIndex}, ev.BackendUid)
	if err := p.bpf.ServiceUpdate(sk, sv); err != nil {
		log.Errorf("Update ServiceUpdate map failed, err:%s", err)
		return err, ek
	}
	return nil, ek
}

// handleWorkloadUnboundServices handles when a workload's belonging services removed
func (p *Processor) handleWorkloadUnboundServices(workload *workloadapi.Workload, unboundedEndpointKeys []bpf.EndpointKey) error {
	log.Debugf("handleWorkloadUnboundServices %s: %v", workload.ResourceName(), unboundedEndpointKeys)
	err := p.deleteEndpointRecords(unboundedEndpointKeys)
	if err != nil {
		log.Errorf("removeResidualServices delete endpoint failed:%v", err)
	}
	return err
}

// handleWorkloadNewBoundServices handles when a workload's belonging services added
func (p *Processor) handleWorkloadNewBoundServices(workload *workloadapi.Workload, newServices []uint32) error {
	var (
		sk = bpf.ServiceKey{}
		sv = bpf.ServiceValue{}
	)

	if len(newServices) == 0 {
		return nil
	}

	log.Debugf("handleWorkloadNewBoundServices %s: %v", workload.ResourceName(), newServices)
	workloadId := p.hashName.Hash(workload.GetUid())
	for _, svcUid := range newServices {
		sk.ServiceId = svcUid
		// the service already stored in map, add endpoint
		if err := p.bpf.ServiceLookup(&sk, &sv); err == nil {
			if sv.LbPolicy == uint32(workloadapi.LoadBalancing_UNSPECIFIED_MODE) { // random mode
				// In random mode, we save all workload to max priority group
				if err, _ = p.addWorkloadToService(&sk, &sv, workloadId, 0); err != nil {
					log.Errorf("addWorkloadToService workload %d service %d failed: %v", workloadId, sk.ServiceId, err)
					return err
				}
			} else { // locality mode
				service := p.ServiceCache.GetService(p.hashName.NumToStr(svcUid))
				if p.locality.LocalityInfo != nil && service != nil {
					prio := p.locality.CalcLocalityLBPrio(workload, service.LoadBalancing.GetRoutingPreference())
					if err, _ = p.addWorkloadToService(&sk, &sv, workloadId, prio); err != nil {
						log.Errorf("addWorkloadToService workload %d service %d priority %d failed: %v", workloadId, sk.ServiceId, prio, err)
						return err
					}
				}
			}
		}
	}
	return nil
}

func (p *Processor) updateWorkloadInBackendMap(workload *workloadapi.Workload) error {
	var (
		err error
		bk  = bpf.BackendKey{}
		bv  = bpf.BackendValue{}
	)

	backendUid := p.hashName.Hash(workload.GetUid())
	log.Debugf("updateWorkloadInBackendMap: workload %s, backendUid: %v", workload.GetUid(), backendUid)

	if waypoint := workload.GetWaypoint(); waypoint != nil && waypoint.GetAddress() != nil {
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
		bk.BackendUid = backendUid
		nets.CopyIpByteFromSlice(&bv.Ip, ip)
		if err = p.bpf.BackendUpdate(&bk, &bv); err != nil {
			log.Errorf("Update backend map failed, err:%s", err)
			return err
		}
	}
	return nil
}

func (p *Processor) updateWorkloadInFrontendMap(workload *workloadapi.Workload) error {
	// we should not store frontend data of hostname network mode pods
	// please see https://github.com/kmesh-net/kmesh/issues/631
	if workload.GetNetworkMode() == workloadapi.NetworkMode_HOST_NETWORK {
		return nil
	}

	backendUid := p.hashName.Hash(workload.GetUid())
	log.Debugf("updateWorkloadInFrontendMap: workload %s, backendUid: %v", workload.GetUid(), backendUid)

	for _, ip := range workload.GetAddresses() {
		svc := p.getServiceByAddress(ip)
		if svc != nil {
			// If the service is found in serviceCache based on the ip address of the workload.
			// we don't update the workload in the frontend map.
			// This occurs in the serviceEntry.
			log.Debugf("workload: %v and service: %v have same ip address: %v", workload.Uid, svc.ResourceName(), ip)
			continue
		}
		if err := p.storePodFrontendData(backendUid, ip); err != nil {
			return fmt.Errorf("storePodFrontendData failed, err:%s", err)
		}
	}
	return nil
}

func (p *Processor) getServiceByAddress(address []byte) *workloadapi.Service {
	networkAddr := cache.NetworkAddress{}
	networkAddr.Address, _ = netip.AddrFromSlice(address)
	if svc := p.ServiceCache.GetServiceByAddr(networkAddr); svc != nil {
		return svc
	}
	return nil
}

func (p *Processor) handleWorkload(workload *workloadapi.Workload) error {
	log.Debugf("handle workload: %s", workload.ResourceName())

	if resolved := p.WaypointCache.AddOrUpdateWorkload(workload); !resolved {
		// If the hostname type waypoint of workload has not been resolved, it will not be processed
		// for the time being. The corresponding waypoint service should be processed immediately, and then
		// it will be handled after the batch resolution is completed in `WaypointCache.Refresh`.
		log.Debugf("waypoint of workload %s can't be resolved immediately, defer processing", workload.ResourceName())
		return nil
	}

	oldWorkload := p.WorkloadCache.GetWorkloadByUid(workload.GetUid())
	// Keep track of the workload no matter it is healthy, unhealthy workload is just for debugging
	p.WorkloadCache.AddOrUpdateWorkload(workload)
	// We only do authz for workloads within same node. So no need to store other unused authorization
	if p.nodeName == workload.Node {
		p.storeWorkloadPolicies(workload.GetUid(), workload.GetAuthorizationPolicies())
	}

	// update kmesh localityCache
	// TODO: recalculate endpoints priority once local locality is set
	if p.locality.LocalityInfo == nil && p.nodeName == workload.GetNode() {
		p.locality.SetLocality(p.nodeName, workload.GetClusterId(), workload.GetNetwork(), workload.GetLocality())
	}

	// Exclude unhealthy workload, which is not ready to serve traffic
	if workload.Status == workloadapi.WorkloadStatus_UNHEALTHY {
		log.Debugf("workload %s is unhealthy", workload.ResourceName())
		// If the workload is updated to unhealthy, we should remove it from the bpf map
		return p.removeWorkloadFromBpfMap(workload)
	}

	// 1. update workload in backend map
	if err := p.updateWorkloadInBackendMap(workload); err != nil {
		return fmt.Errorf("updateWorkloadInBackendMap %s failed: %v", workload.Uid, err)
	}

	// 2~3. update workload in endpoint map and service map
	unboundedEndpointKeys, newServices := p.compareWorkloadServices(workload)
	if err := p.handleWorkloadUnboundServices(workload, unboundedEndpointKeys); err != nil {
		return fmt.Errorf("handleWorkloadUnboundServices %s failed: %v", workload.ResourceName(), err)
	}

	// Add new services associated with the workload
	if err := p.handleWorkloadNewBoundServices(workload, newServices); err != nil {
		return fmt.Errorf("handleWorkloadNewBoundServices %s failed: %v", workload.ResourceName(), err)
	}

	// 4. update workload in frontend map
	if err := p.updateWorkloadInFrontendMap(workload); err != nil {
		return fmt.Errorf("updateWorkloadInFrontendMap %s failed: %v", workload.Uid, err)
	}
	if oldWorkload != nil {
		// To be able to find a workload in the workloadCache,
		// you need to determine whether the address of the workload has changed or not.
		// And clean up the residue
		newWorkloadAddresses := workload.GetAddresses()
		oldWorkloadAddresses := oldWorkload.GetAddresses()

		// Because there is only one address in the workload, a direct comparison can be made to
		// determine whether the old data needs to be deleted or not.
		if !slices.Equal(newWorkloadAddresses[0], oldWorkloadAddresses[0]) {
			err := p.deleteFrontendByIp(oldWorkloadAddresses)
			if err != nil {
				return fmt.Errorf("frontend map delete failed: %v", err)
			}
		}
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

func (p *Processor) updateServiceFrontendMap(serviceId uint32, service *workloadapi.Service) error {
	var (
		err error
		fk  = bpf.FrontendKey{}
		fv  = bpf.FrontendValue{}
	)

	fv.UpstreamId = serviceId
	for _, networkAddress := range service.GetAddresses() {
		nets.CopyIpByteFromSlice(&fk.Ip, networkAddress.Address)
		if err = p.bpf.FrontendUpdate(&fk, &fv); err != nil {
			log.Errorf("frontend map update err:%s", err)
			return err
		}
	}
	return nil
}

func (p *Processor) updateEndpointOneByOne(serviceId uint32, epsUpdate []cache.Endpoint, toLLb bool) error {
	if len(epsUpdate) == 0 {
		return nil
	}

	// When calling deleteEndpointRecords, it causes the endpoint to be updated and swaps it with the endpoint
	// with the highest BackendIndex in the priority, leading to a Endpoint shift. Therefore, we
	// sort Endpoint slice in reverse order to ensure that the BackendIndex of the endpoints updated later
	// remains unchanged.
	sort.Slice(epsUpdate, func(i, j int) bool {
		if epsUpdate[i].Prio == epsUpdate[j].Prio {
			return epsUpdate[i].BackendIndex > epsUpdate[j].BackendIndex
		}
		return epsUpdate[i].Prio > epsUpdate[j].Prio
	})

	service := p.ServiceCache.GetService(p.hashName.NumToStr(serviceId))

	for _, ep := range epsUpdate {
		ek := bpf.EndpointKey{
			ServiceId:    ep.ServiceId,
			Prio:         ep.Prio,
			BackendIndex: ep.BackendIndex,
		}
		ev := bpf.EndpointValue{}
		if err := p.bpf.EndpointLookup(&ek, &ev); err != nil { // get backend Uid
			return fmt.Errorf("lookup endpoint %#v failed: %v", ek, err)
		}

		// Calc Priority
		var prio uint32 = 0
		if toLLb {
			workload := p.WorkloadCache.GetWorkloadByUid(p.hashName.NumToStr(ev.BackendUid))
			prio = p.locality.CalcLocalityLBPrio(workload, service.LoadBalancing.GetRoutingPreference())
		}

		// If an endpoint's priority is not changed, we donot need to update the map.
		if ek.Prio == prio {
			continue
		}

		// addWorkloadToService and deleteEndpointRecords will update service map each time, so we need look up it each time.
		sKey := bpf.ServiceKey{ServiceId: serviceId}
		sValue := bpf.ServiceValue{}
		if err := p.bpf.ServiceLookup(&sKey, &sValue); err != nil {
			return fmt.Errorf("lookup service %v failed: %v", serviceId, err)
		}

		// add ek first to another priority group
		if err, _ := p.addWorkloadToService(&sKey, &sValue, ev.BackendUid, prio); err != nil {
			return fmt.Errorf("update endpoint %d priority to %d failed: %v", ev.BackendUid, prio, err)
		}
		epKeys := []bpfcache.EndpointKey{ek}
		// delete ek from old priority group
		if err := p.deleteEndpointRecords(epKeys); err != nil {
			return fmt.Errorf("delete endpoint %d from old priority group %d failed: %v", ev.BackendUid, ek.Prio, err)
		}
	}
	return nil
}

// updateEndpointPriority is called when service lb policy is changed to update the endpoint priority.
// toLLb indicates whether we are performing a locality load balance update.
// If toLLb is true, it means we need to calculate priority; otherwise,
// it represents a random strategy, in which case we just set the priority to 0.
func (p *Processor) updateEndpointPriority(serviceId uint32, toLLb bool) error {
	endpoints := p.EndpointCache.List(serviceId)
	endpointSlice := make([]cache.Endpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		endpointSlice = append(endpointSlice, endpoint)
	}
	if toLLb {
		return p.updateEndpointOneByOne(serviceId, endpointSlice, toLLb)
	} else {
		filtered := slices.Filter(endpointSlice, func(e cache.Endpoint) bool {
			return e.Prio > 0
		})
		return p.updateEndpointOneByOne(serviceId, filtered, toLLb)
	}
}

func (p *Processor) updateServiceMap(service, oldService *workloadapi.Service) error {
	sk := bpf.ServiceKey{}
	oldServiceInfo := bpf.ServiceValue{}
	newServiceInfo := bpf.ServiceValue{}

	serviceName := service.ResourceName()
	waypoint := service.Waypoint
	ports := service.Ports
	lb := service.LoadBalancing

	sk.ServiceId = p.hashName.Hash(serviceName)
	newServiceInfo.LbPolicy = uint32(lb.GetMode()) // set loadbalance mode

	if waypoint != nil && waypoint.GetAddress() != nil {
		nets.CopyIpByteFromSlice(&newServiceInfo.WaypointAddr, waypoint.GetAddress().Address)
		newServiceInfo.WaypointPort = nets.ConvertPortToBigEndian(waypoint.GetHboneMtlsPort())
	}

	for i, port := range ports {
		if i >= bpf.MaxPortNum {
			log.Warnf("exceed the max port count, current only support maximum of 10 ports, service: %s", serviceName)
			break
		}

		newServiceInfo.ServicePort[i] = nets.ConvertPortToBigEndian(port.ServicePort)
		if strings.Contains(serviceName, "waypoint") {
			newServiceInfo.TargetPort[i] = nets.ConvertPortToBigEndian(KmeshWaypointPort)
		} else if port.TargetPort == 0 {
			// NOTE: Target port could be unset in servicen entry, in which case it should
			// be consistent with the Service Port.
			newServiceInfo.TargetPort[i] = nets.ConvertPortToBigEndian(port.ServicePort)
		} else {
			newServiceInfo.TargetPort[i] = nets.ConvertPortToBigEndian(port.TargetPort)
		}
	}

	if err := p.bpf.ServiceLookup(&sk, &oldServiceInfo); err == nil {
		// Because it is the oldServiceInfo that is stored in the service map.
		// It is obtained by looking up the table rather than rebuilding the oldService
		// Already exists, it means this is service update.
		newServiceInfo.EndpointCount = oldServiceInfo.EndpointCount
		// if it is a policy update
		if newServiceInfo.LbPolicy != oldServiceInfo.LbPolicy {
			// transit from locality loadbalance to random
			if newServiceInfo.LbPolicy == uint32(workloadapi.LoadBalancing_UNSPECIFIED_MODE) {
				// In locality load balancing mode, the workloads are stored according to the calculated corresponding priorities.
				// When switching from locality load balancing mode to random, we first update the endpoint map, as at this point,
				// there might not be any workload with the highest priority, and directly switching the service's LB policy could
				// lead to unexpected service disruptions.
				if err = p.updateEndpointPriority(sk.ServiceId, false); err != nil { // this will change bpf map totally
					return fmt.Errorf("update endpoint priority failed: %v", err)
				}
				updateServiceInfo := bpf.ServiceValue{}
				if err = p.bpf.ServiceLookup(&sk, &updateServiceInfo); err != nil {
					return fmt.Errorf("service map lookup %v failed: %v", sk.ServiceId, err)
				}
				updateServiceInfo.LbPolicy = newServiceInfo.LbPolicy
				if err = p.bpf.ServiceUpdate(&sk, &updateServiceInfo); err != nil {
					return fmt.Errorf("service map update failed: %v", err)
				}
				return nil
			} else if oldServiceInfo.LbPolicy == uint32(workloadapi.LoadBalancing_UNSPECIFIED_MODE) {
				// from random to locality loadbalance
				// In random mode, the workloads are stored with the highest priority. When switching from random mode to locality
				// load balancing, we first update the service map to quickly initiate the transition of the strategy. Subsequently,
				// we update the endpoint map. During this update process, the load balancer may briefly exhibit abnormal random behavior,
				// after which it will fully transition to the locality load balancing mode.
				if err = p.bpf.ServiceUpdate(&sk, &newServiceInfo); err != nil {
					return fmt.Errorf("service map update lb policy failed: %v", err)
				}

				if err = p.updateEndpointPriority(sk.ServiceId, true); err != nil {
					return fmt.Errorf("update endpoint priority failed: %v", err)
				}
				return nil
			}
		}

		// Compare the addresses of the old and new maps to avoid residual.
		// If the data can be found in the km_service map, it is also stored in the serviceCache.
		newServiceAddress := service.GetIpAddresses()
		oldServiceAddress := oldService.GetIpAddresses()
		removeServiceAddress := nets.CompareIpByte(newServiceAddress, oldServiceAddress)
		if err := p.deleteFrontendByIp(removeServiceAddress); err != nil {
			return fmt.Errorf("frontend map delete failed: %v", err)
		}
	}

	// normal update
	if err := p.bpf.ServiceUpdate(&sk, &newServiceInfo); err != nil {
		return fmt.Errorf("service map update failed: %v", err)
	}

	if err := p.updateServiceFrontendMap(sk.ServiceId, service); err != nil {
		return fmt.Errorf("updateServiceFrontendMap failed: %v", err)
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
	if service.Waypoint != nil && service.GetWaypoint().GetAddress() != nil && len(service.Addresses) != 0 {
		// Currently istiod only set the waypoint address to the first address of the service
		// When waypoints of different granularities are deployed together, the only waypoint service to be determined
		// is whether it contains port 15021, ref: https://github.com/kmesh-net/kmesh/issues/691
		// TODO: remove when upstream istiod will not set the waypoint address for itself
		if slices.Equal(service.GetWaypoint().GetAddress().Address, service.Addresses[0].Address) || containsPort(15021) {
			service.Waypoint = nil
		}
	}

	if resolved := p.WaypointCache.AddOrUpdateService(service); !resolved {
		// If the hostname type waypoint of service has not been resolved, it will not be processed
		// for the time being. The corresponding waypoint service should be processed immediately, and then
		// it will be handled after the batch resolution is completed in `WaypointCache.Refresh`.
		log.Debugf("waypoint of service %s can't be resolved immediately, defer processing", service.ResourceName())
		return nil
	}

	oldService := p.ServiceCache.GetService(service.ResourceName())
	p.ServiceCache.AddOrUpdateService(service)
	// update service and endpoint map
	if err := p.updateServiceMap(service, oldService); err != nil {
		log.Errorf("update service %s maps failed: %v", service.ResourceName(), err)
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

	if err := p.removeWorkloadResources(workloadNames); err != nil {
		log.Errorf("removeWorkloadResources failed: %v", err)
	}
	if err := p.removeServiceResources(serviceNames); err != nil {
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
			log.Errorf("unknown type, should not reach here")
		}
	}

	p.handleServicesAndWorkloads(services, workloads)

	p.handleRemovedAddresses(rsp.RemovedResources)
	p.once.Do(p.handleRemovedAddressesDuringRestart)
	return err
}

// Mainly for the convenience of testing.
func (p *Processor) handleServicesAndWorkloads(services []*workloadapi.Service, workloads []*workloadapi.Workload) {
	var servicesToRefresh []*workloadapi.Service
	for _, service := range services {
		if err := p.handleService(service); err != nil {
			log.Errorf("handle service %v failed, err: %v", service.ResourceName(), err)
		}
		svcs, wls := p.WaypointCache.Refresh(service)
		servicesToRefresh = append(servicesToRefresh, svcs...)
		// Directly add deferred workload to workloads.
		workloads = append(workloads, wls...)
	}

	// Handle services that are deferred due to waypoint hostname resolution.
	for _, service := range servicesToRefresh {
		if err := p.handleService(service); err != nil {
			log.Errorf("handle deferred service %v failed, err: %v", service.ResourceName(), err)
		}
	}

	for _, workload := range workloads {
		if err := p.handleWorkload(workload); err != nil {
			log.Errorf("handle workload %s failed, err: %v", workload.ResourceName(), err)
		}
	}
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
	for str, num := range p.hashName.GetStrToNum() {
		if p.WorkloadCache.GetWorkloadByUid(str) == nil && p.ServiceCache.GetService(str) == nil {
			log.Debugf("GetWorkloadByUid and GetService nil:%v", str)

			bk.BackendUid = num
			sk.ServiceId = num
			if err := p.bpf.BackendLookup(&bk, &bv); err == nil {
				log.Debugf("found BackendValue: [%#v] and removeWorkloadFromBpfMap", bv)
				dummyWorkload := &workloadapi.Workload{Uid: str}
				if err := p.removeWorkloadFromBpfMap(dummyWorkload); err != nil {
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
		authPolicy := &security.Authorization{}
		if err := anypb.UnmarshalTo(resource.Resource, authPolicy, proto.UnmarshalOptions{}); err != nil {
			log.Errorf("unmarshal failed, err: %v", err)
			continue
		}
		log.Debugf("handle authorization policy %s, auth %s", resource.GetName(), authPolicy.String())
		if err := rbac.UpdatePolicy(authPolicy); err != nil {
			return err
		}

		policyKey := authPolicy.ResourceName()
		if err := maps_v2.AuthorizationUpdate(p.hashName.Hash(policyKey), authPolicy); err != nil {
			return fmt.Errorf("AuthorizationUpdate %s failed %v ", policyKey, err)
		}
	}

	// delete resource by name
	for _, resourceName := range rsp.GetRemovedResources() {
		rbac.RemovePolicy(resourceName)
		if err := maps_v2.AuthorizationDelete(p.hashName.Hash(resourceName)); err != nil {
			log.Errorf("remove authorization policy %s failed :%v", resourceName, err)
		}
		log.Debugf("remove authorization policy %s", resourceName)
	}

	p.authzOnce.Do(func() {
		p.handleRemovedAuthzPolicyDuringRestart(rbac)
	})
	return nil
}

// When processing the Authorization's response for the first time,
// fetch the data from the /mnt/workload_hash_name.yaml file
// and compare it with the data in the cache.
func (p *Processor) handleRemovedAuthzPolicyDuringRestart(rbac *auth.Rbac) {
	var (
		policyValue = security_v2.Authorization{}
	)

	log.Infof("reload authz config from last epoch")
	/* We traverse hashName, if there is a record exists in bpf map
	 * but not in usercache, that means the data in the bpf map load
	 * from the last epoch is inconsistent with the data that should
	 * actually be stored now. then we should delete it from bpf map
	 */
	policyCache := rbac.GetAllPolicies()
	for str, num := range p.hashName.GetStrToNum() {
		if _, exists := policyCache[str]; !exists {
			if err := maps_v2.AuthorizationLookup(num, &policyValue); err == nil {
				log.Debugf("Find policy: [%v:%v] Remove authz policy", str, num)
				if err := maps_v2.AuthorizationDelete(num); err != nil {
					log.Errorf("RemoveWorkloadResource failed: %v", err)
				}
			}
		}
	}
}

// deleteEndpointRecords deletes endpoint from endpoint map and moves the last endpoints to occupy the deleted position,
// then simultaneously update service map's endpoint count.
func (p *Processor) deleteEndpointRecords(endpointKeys []bpf.EndpointKey) error {
	var (
		sk = bpf.ServiceKey{}
		sv = bpf.ServiceValue{}
		ev = bpf.EndpointValue{}
	)

	if len(endpointKeys) == 0 {
		return nil
	}

	// sort endpointKeys, first delete the endpoint with the highest priority and the largest BackendIndex
	// so that it will not influence the backendInde of the other endpoints that deleted later
	sort.Slice(endpointKeys, func(i, j int) bool {
		if endpointKeys[i].Prio == endpointKeys[j].Prio {
			return endpointKeys[i].BackendIndex > endpointKeys[j].BackendIndex
		}
		return endpointKeys[i].Prio > endpointKeys[j].Prio
	})

	for _, ek := range endpointKeys {
		sk.ServiceId = ek.ServiceId
		if err := p.bpf.ServiceLookup(&sk, &sv); err == nil {
			if err = p.bpf.EndpointLookup(&ek, &ev); err != nil {
				log.Errorf("Lookup endpoint %#v failed: %v", ek, err)
				continue
			}

			if err := p.deleteEndpoint(ek, ev, sv, sk); err != nil {
				log.Errorf("deleteEndpoint failed: %v", err)
				continue
			}
			p.EndpointCache.DeleteEndpointWithPriority(ek.ServiceId, ev.BackendUid, ek.Prio)
		} else {
			// service not exist, we should also delete the endpoint
			log.Warnf("service %d not found, should not occur: %v", ek.ServiceId, err)

			if err = p.bpf.EndpointLookup(&ek, &ev); err != nil {
				log.Errorf("Lookup endpoint %#v failed: %s", ek, err)
				continue
			}
			// delete endpoint from map
			if err := p.bpf.EndpointDelete(&ek); err != nil {
				log.Errorf("EndpointDelete [%#v] failed: %v", ek, err)
				continue
			}
			p.EndpointCache.DeleteEndpointWithPriority(ek.ServiceId, ev.BackendUid, ek.Prio)
		}
	}
	return nil
}

// In order to make sure the bpf prog can always get the healthy endpoint, we should update the bpf map in the following order:
// 1. replace the current endpoint with the last endpoint
// 2. update the service map's endpoint count
// 3. delete the last endpoint
func (p *Processor) deleteEndpoint(ek bpf.EndpointKey, ev bpf.EndpointValue, sv bpf.ServiceValue, sk bpf.ServiceKey) error {
	if err := p.bpf.EndpointSwap(ek.BackendIndex, ev.BackendUid, sv.EndpointCount[ek.Prio], sk.ServiceId, ek.Prio); err != nil {
		log.Errorf("swap workload endpoint index failed: %s", err)
		return err
	}

	sv.EndpointCount[ek.Prio] = sv.EndpointCount[ek.Prio] - 1
	if err := p.bpf.ServiceUpdate(&sk, &sv); err != nil {
		log.Errorf("ServiceUpdate %#v failed: %v", sk, err)
		return err
	}

	lastKey := &bpf.EndpointKey{
		ServiceId:    sk.ServiceId,
		Prio:         ek.Prio,
		BackendIndex: sv.EndpointCount[ek.Prio] + 1,
	}
	if err := p.bpf.EndpointDelete(lastKey); err != nil {
		log.Errorf("EndpointDelete [%#v] failed: %v", lastKey, err)
		return err
	}
	return nil
}

func (p *Processor) storeWorkloadPolicies(uid string, polices []string) {
	var (
		key   = bpf.WorkloadPolicyKey{}
		value = bpf.WorkloadPolicyValue{}
	)
	if len(polices) == 0 {
		return
	}
	key.WorklodId = p.hashName.Hash(uid)
	for i, v := range polices {
		if i < len(value.PolicyIds) {
			value.PolicyIds[i] = p.hashName.Hash(v)
		} else {
			log.Warnf("Exceeded the number of elements in PolicyIds.")
			break
		}
	}

	if err := p.bpf.WorkloadPolicyUpdate(&key, &value); err != nil {
		log.Errorf("storeWorkloadPolicies failed, workload %s, err: %s", uid, err)
	}
}

func (p *Processor) deleteWorkloadPolicies(uid uint32) {
	key := bpf.WorkloadPolicyKey{
		WorklodId: uid,
	}
	if err := p.bpf.WorkloadPolicyDelete(&key); err != nil {
		log.Errorf("delete workload policy failed err: %v", err)
	}
}

func (p *Processor) deleteFrontendByIp(addresses [][]byte) error {
	frontKey := bpf.FrontendKey{}
	for _, address := range addresses {
		nets.CopyIpByteFromSlice(&frontKey.Ip, address)
		if err := p.bpf.FrontendDelete(&frontKey); err != nil {
			return err
		}
	}

	return nil
}
