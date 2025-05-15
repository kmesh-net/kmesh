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

package cache

import (
	"sync"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/bpfcache"
)

type WaypointCache interface {
	// AddOrUpdateService add or update service in this cache, return true if the
	// service's waypoint doesn't need to be resolved or resolved successfully.
	AddOrUpdateService(svc *workloadapi.Service) bool
	DeleteService(resourceName string)
	// AddOrUpdateWorkload add or update workload in this cache, return true if the
	// workload's waypoint doesn't need to be resolved or resolved successfully.
	AddOrUpdateWorkload(workload *workloadapi.Workload) bool
	DeleteWorkload(uid string)

	GetAssociatedObjectsByResourceName(name string) *waypointAssociatedObjects

	// Refresh is used to process waypoint service.
	// If it is a newly added waypoint service, it returns a series of services and workloads that need to be updated
	// whose hostname type waypoint address should be converted to IP address type. These services and workloads were
	// processed earlier but the hostname of the related waypoint could not be resolved at that time.
	Refresh(svc *workloadapi.Service) ([]*workloadapi.Service, []*workloadapi.Workload)
}

type waypointCache struct {
	mutex sync.RWMutex

	serviceCache ServiceCache

	// NOTE: The following data structure is used to change the waypoint
	// address of type hostname in the service or workload to type ip address. Because of
	// the order in which services are processed, it may be possible that corresponding
	// waypoint service can't be found when processing the service or workload. The waypoint associated
	// with a service or a workload can also changed at any time, so we need the following maps to track
	// the relationship between service & workload and its waypoint.

	// Used to track a waypoint and all services and workloads associated with it.
	// Keyed by waypoint service resource name, valued by its associated services and workloads.
	//
	// ***
	// When a service's or workload's waypoint needs to be converted, first check whether the waypoint can be found in this map.
	// If it can be found, convert it directly. Otherwise, add it to the waypointAssociatedServices and wait.
	// When the corresponding waypoint service is added to the cache, it will be processed and returned uniformly.
	// ***
	waypointAssociatedObjects map[string]*waypointAssociatedObjects

	// Used to locate relevant waypoint when deleting or updating service.
	// Keyed by service resource name, valued by associated waypoint's resource name.
	serviceToWaypoint map[string]string

	// Used to locate relevant waypoint when deleting or updating workload.
	// Keyed by workload uid, valued by associated waypoint's resource name.
	workloadToWaypoint map[string]string
}

func NewWaypointCache(serviceCache ServiceCache, bpfCache *bpfcache.Cache) *waypointCache {
	return &waypointCache{
		serviceCache:              serviceCache,
		waypointAssociatedObjects: make(map[string]*waypointAssociatedObjects),
		serviceToWaypoint:         make(map[string]string),
		workloadToWaypoint:        make(map[string]string),
	}
}

func (w *waypointCache) AddOrUpdateService(svc *workloadapi.Service) bool {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	resourceName := svc.ResourceName()
	// If this is a service without waypoint or with an IP address type waypoint, no processing is required and
	// return directly.
	if svc.GetWaypoint() == nil || svc.GetWaypoint().GetAddress() != nil {
		// Service may become unassociated with waypoint.
		if waypoint, ok := w.serviceToWaypoint[resourceName]; ok {
			delete(w.serviceToWaypoint, resourceName)
			w.waypointAssociatedObjects[waypoint].deleteService(resourceName)
		}
		return true
	}

	var ret bool

	// If this is a svc with hostname waypoint.
	hostname := svc.GetWaypoint().GetHostname()
	waypointResourceName := hostname.GetNamespace() + "/" + hostname.GetHostname()

	if waypoint, ok := w.serviceToWaypoint[resourceName]; ok && waypoint != waypointResourceName {
		// Service updated associated waypoint, delete previous association first.
		delete(w.serviceToWaypoint, resourceName)
		w.waypointAssociatedObjects[waypoint].deleteService(resourceName)
	}

	log.Debugf("Update svc %s with waypoint %s", svc.ResourceName(), waypointResourceName)
	if associated, ok := w.waypointAssociatedObjects[waypointResourceName]; ok {
		if associated.isResolved() {
			// The waypoint corresponding to this service has been resolved.
			updateServiceWaypoint(svc, associated.WaypointAddress())
			ret = true
		}
	} else {
		// Try to find the waypoint service from the cache.
		waypointService := w.serviceCache.GetService(waypointResourceName)
		var addr *workloadapi.NetworkAddress
		if waypointService != nil && len(waypointService.GetAddresses()) != 0 {
			addr = waypointService.GetAddresses()[0]
			updateServiceWaypoint(svc, waypointService.GetAddresses()[0])
			ret = true
		}
		w.waypointAssociatedObjects[waypointResourceName] = newAssociatedObjects(addr)
		log.Infof("svc resourceName is: %v", waypointResourceName)
		log.Infof("waypointCache is: %v", w.waypointAssociatedObjects)
	}
	w.serviceToWaypoint[resourceName] = waypointResourceName
	// Anyway, add svc to the association list.
	w.waypointAssociatedObjects[waypointResourceName].addService(resourceName, svc)

	return ret
}

func (w *waypointCache) DeleteService(resourceName string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	// This service has waypoint.
	if waypoint, ok := w.serviceToWaypoint[resourceName]; ok {
		delete(w.serviceToWaypoint, resourceName)
		if associate, ok := w.waypointAssociatedObjects[waypoint]; ok {
			associate.deleteService(resourceName)
		}
	}

	// This may be a waypoint service.
	delete(w.waypointAssociatedObjects, resourceName)
}

func (w *waypointCache) GetAssociatedObjectsByResourceName(name string) *waypointAssociatedObjects {
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	if v, ok := w.waypointAssociatedObjects[name]; ok {
		return v
	}
	return nil
}

func (w *waypointCache) AddOrUpdateWorkload(workload *workloadapi.Workload) bool {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	uid := workload.GetUid()
	// If this is a workload with waypoint or with an IP address type waypoint, no processing is required and
	// return directly.
	if workload.GetWaypoint() == nil || workload.GetWaypoint().GetAddress() != nil {
		// Workload may become unassociated with waypoint.
		if waypoint, ok := w.workloadToWaypoint[uid]; ok {
			delete(w.workloadToWaypoint, uid)
			w.waypointAssociatedObjects[waypoint].deleteWorkload(uid)
		}
		return true
	}

	var ret bool

	// If this is a svc with hostname waypoint.
	hostname := workload.GetWaypoint().GetHostname()
	waypointResourceName := hostname.GetNamespace() + "/" + hostname.GetHostname()

	if waypoint, ok := w.workloadToWaypoint[uid]; ok && waypoint != waypointResourceName {
		// Workload updated associated waypoint, delete previous association first.
		delete(w.workloadToWaypoint, uid)
		w.waypointAssociatedObjects[waypoint].deleteWorkload(uid)
	}

	log.Debugf("Update workload %s with waypoint %s", uid, waypointResourceName)
	if associated, ok := w.waypointAssociatedObjects[waypointResourceName]; ok {
		if associated.isResolved() {
			// The waypoint corresponding to this service has been resolved.
			updateWorkloadWaypoint(workload, associated.WaypointAddress())
			ret = true
		}
	} else {
		// Try to find the waypoint service from the cache.
		waypointService := w.serviceCache.GetService(waypointResourceName)
		var addr *workloadapi.NetworkAddress
		if waypointService != nil && len(waypointService.GetAddresses()) != 0 {
			addr = waypointService.GetAddresses()[0]
			updateWorkloadWaypoint(workload, waypointService.GetAddresses()[0])
			ret = true
		}
		w.waypointAssociatedObjects[waypointResourceName] = newAssociatedObjects(addr)
	}
	w.workloadToWaypoint[uid] = waypointResourceName
	// Anyway, add svc to the association list.
	w.waypointAssociatedObjects[waypointResourceName].addWorkload(uid, workload)

	return ret
}

func (w *waypointCache) DeleteWorkload(uid string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if waypoint, ok := w.workloadToWaypoint[uid]; ok {
		delete(w.workloadToWaypoint, uid)
		if associated, ok := w.waypointAssociatedObjects[waypoint]; ok {
			associated.deleteWorkload(uid)
		}
	}
}

func (w *waypointCache) Refresh(svc *workloadapi.Service) ([]*workloadapi.Service, []*workloadapi.Workload) {
	if len(svc.GetAddresses()) == 0 {
		return nil, nil
	}

	address := svc.GetAddresses()[0]
	resourceName := svc.ResourceName()

	w.mutex.Lock()
	defer w.mutex.Unlock()

	// If this svc is a waypoint service, may need refreshing.
	if associated, ok := w.waypointAssociatedObjects[resourceName]; ok {
		waypointAddr := associated.WaypointAddress()
		if waypointAddr != nil && waypointAddr.String() == address.String() {
			return nil, nil
		}

		log.Debugf("Refreshing services associated with waypoint %s", resourceName)
		return associated.update(address)
	}

	return nil, nil
}

type waypointAssociatedObjects struct {
	mutex sync.RWMutex
	// IP address of waypoint.
	// If it is nil, it means that the waypoint service has not been processed yet.
	address *workloadapi.NetworkAddress

	// Associated services of this waypoint.
	// The key of this map is service resource name and value is corresponding service structure.
	services map[string]*workloadapi.Service

	// Associated workloads of this waypoint.
	// The key of this map is workload uid and value is corresponding workload structure.
	workloads map[string]*workloadapi.Workload
}

func newAssociatedObjects(addr *workloadapi.NetworkAddress) *waypointAssociatedObjects {
	return &waypointAssociatedObjects{
		address:   addr,
		services:  make(map[string]*workloadapi.Service),
		workloads: make(map[string]*workloadapi.Workload),
	}
}

func (w *waypointAssociatedObjects) isResolved() bool {
	return w.address != nil
}

func (w *waypointAssociatedObjects) WaypointAddress() *workloadapi.NetworkAddress {
	return w.address
}

func (w *waypointAssociatedObjects) update(addr *workloadapi.NetworkAddress) ([]*workloadapi.Service, []*workloadapi.Workload) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.address = addr

	svcs := []*workloadapi.Service{}
	workloads := []*workloadapi.Workload{}

	for _, svc := range w.services {
		updateServiceWaypoint(svc, addr)
		svcs = append(svcs, svc)
	}

	for _, workload := range w.workloads {
		updateWorkloadWaypoint(workload, addr)
		workloads = append(workloads, workload)
	}

	return svcs, workloads
}

func (w *waypointAssociatedObjects) addService(resourceName string, service *workloadapi.Service) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.services[resourceName] = service
}

func (w *waypointAssociatedObjects) deleteService(resourceName string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	delete(w.services, resourceName)
}

func (w *waypointAssociatedObjects) addWorkload(uid string, workload *workloadapi.Workload) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.workloads[uid] = workload
}

func (w *waypointAssociatedObjects) deleteWorkload(uid string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	delete(w.workloads, uid)
}

func updateServiceWaypoint(svc *workloadapi.Service, addr *workloadapi.NetworkAddress) {
	svc.GetWaypoint().Destination = &workloadapi.GatewayAddress_Address{
		Address: addr,
	}
}

func updateWorkloadWaypoint(workload *workloadapi.Workload, addr *workloadapi.NetworkAddress) {
	workload.GetWaypoint().Destination = &workloadapi.GatewayAddress_Address{
		Address: addr,
	}
}
