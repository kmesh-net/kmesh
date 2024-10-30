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
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("service_cache")

type ServiceCache interface {
	List() []*workloadapi.Service
	AddOrUpdateService(svc *workloadapi.Service)
	DeleteService(resourceName string)
	GetService(resourceName string) *workloadapi.Service
	RefreshWaypoint(svc *workloadapi.Service) []*workloadapi.Service
}

type serviceCache struct {
	mutex sync.RWMutex
	// keyed by namespace/hostname->service
	servicesByResourceName map[string]*workloadapi.Service

	// NOTE: The following data structure is used to change the waypoint
	// address of type hostname in the service to type ip address. Because of
	// the order in which services are processed, it may be possible that corresponding
	// waypoint service can't be found when processing the service. The waypoint associated
	// with a service can also changed at any time, so we need the following maps to track
	// the relationship between service and its waypoint.

	// Used to track a waypoint and all services associated with it.
	// Keyed by waypoint service resource name, valued by its associated services.
	//
	// ***
	// When a service's waypoint needs to be converted, first check whether the waypoint can be found in this map.
	// If it can be found, convert it directly. Otherwise, add it to the waypointAssociatedServices and wait.
	// When the corresponding waypoint service is added to the cache, it will be processed and returned uniformly.
	// ***
	waypointToServices map[string]*waypointAssociatedServices

	// Used to locate relevant waypoint when deleting or updating service.
	// Keyed by service resource name, valued by associated waypoint's resource name.
	serviceToWaypoint map[string]string
}

type waypointAssociatedServices struct {
	mutex sync.RWMutex
	// IP address of waypoint.
	// If it is nil, it means that the waypoint service has not been processed yet.
	address *workloadapi.NetworkAddress

	// Associated services of this waypoint.
	// The key of this map is service resource name and value is corresponding service structure.
	services map[string]*workloadapi.Service
}

func newWaypointAssociatedServices(addr *workloadapi.NetworkAddress) *waypointAssociatedServices {
	return &waypointAssociatedServices{
		address:  addr,
		services: make(map[string]*workloadapi.Service),
	}
}

func (w *waypointAssociatedServices) isResolved() bool {
	return w.address != nil
}

func (w *waypointAssociatedServices) waypointAddress() *workloadapi.NetworkAddress {
	return w.address
}

func (w *waypointAssociatedServices) update(addr *workloadapi.NetworkAddress) []*workloadapi.Service {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.address = addr

	res := []*workloadapi.Service{}

	for _, svc := range w.services {
		updateWaypoint(svc, addr)
		res = append(res, svc)
	}

	return res
}

func (w *waypointAssociatedServices) deleteService(resourceName string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	delete(w.services, resourceName)
}

func (w *waypointAssociatedServices) addService(resourceName string, service *workloadapi.Service) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.services[resourceName] = service
}

func NewServiceCache() *serviceCache {
	return &serviceCache{
		servicesByResourceName: make(map[string]*workloadapi.Service),
		waypointToServices:     make(map[string]*waypointAssociatedServices),
		serviceToWaypoint:      make(map[string]string),
	}
}

func (s *serviceCache) AddOrUpdateService(svc *workloadapi.Service) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	resourceName := svc.ResourceName()

	s.servicesByResourceName[resourceName] = svc

	// If this is a service with an IP address type waypoint, no processing is required and
	// return directly.
	if svc.GetWaypoint() == nil || svc.GetWaypoint().GetAddress() != nil {
		// Service may become unassociated with waypoint.
		if waypoint, ok := s.serviceToWaypoint[resourceName]; ok {
			delete(s.serviceToWaypoint, resourceName)
			s.waypointToServices[waypoint].deleteService(resourceName)
		}
		return
	}

	// If this is a svc with hostname waypoint.
	hostname := svc.GetWaypoint().GetHostname()
	waypointResourceName := hostname.GetNamespace() + "/" + hostname.GetHostname()

	if waypoint, ok := s.serviceToWaypoint[resourceName]; ok && waypoint != waypointResourceName {
		// Service updated associated waypoint, delete previous association first.
		delete(s.serviceToWaypoint, resourceName)
		s.waypointToServices[waypoint].deleteService(resourceName)
	}

	log.Debugf("Update svc %s with waypoint %s", svc.ResourceName(), waypointResourceName)
	if associated, ok := s.waypointToServices[waypointResourceName]; ok {
		if associated.isResolved() {
			// The waypoint corresponding to this service has been resolved.
			updateWaypoint(svc, associated.waypointAddress())
		}
	} else {
		// Try to find the waypoint service from the cache.
		waypointService := s.servicesByResourceName[waypointResourceName]
		var addr *workloadapi.NetworkAddress
		if waypointService != nil && len(waypointService.GetAddresses()) != 0 {
			addr = waypointService.GetAddresses()[0]
			updateWaypoint(svc, waypointService.GetAddresses()[0])
		}
		s.waypointToServices[waypointResourceName] = newWaypointAssociatedServices(addr)
	}
	s.serviceToWaypoint[resourceName] = waypointResourceName
	// Anyway, add svc to the association list.
	s.waypointToServices[waypointResourceName].addService(resourceName, svc)
}

func (s *serviceCache) DeleteService(resourceName string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.servicesByResourceName, resourceName)

	// This service has waypoint.
	if waypoint, ok := s.serviceToWaypoint[resourceName]; ok {
		delete(s.serviceToWaypoint, resourceName)
		s.waypointToServices[waypoint].deleteService(resourceName)
	}

	// This is a waypoint service.
	if _, ok := s.waypointToServices[resourceName]; ok {
		delete(s.waypointToServices, resourceName)
	}
}

func (s *serviceCache) List() []*workloadapi.Service {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	out := make([]*workloadapi.Service, 0, len(s.servicesByResourceName))
	for _, svc := range s.servicesByResourceName {
		out = append(out, svc)
	}

	return out
}

func (s *serviceCache) GetService(resourceName string) *workloadapi.Service {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.servicesByResourceName[resourceName]
}

// RefreshWaypoint is used to process waypoint service.
// If it is a newly added waypoint service, it returns a series of services that need to be updated
// whose hostname type waypoint address should be converted to IP address type. These services were
// processed earlier but the hostname of the related waypoint could not be resolved at that time.
func (s *serviceCache) RefreshWaypoint(svc *workloadapi.Service) []*workloadapi.Service {
	if len(svc.GetAddresses()) == 0 {
		return nil
	}

	address := svc.GetAddresses()[0]
	resourceName := svc.ResourceName()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	res := []*workloadapi.Service{}
	// If this svc is a waypoint service, may need refreshing.
	if associated, ok := s.waypointToServices[resourceName]; ok {
		waypointAddr := associated.waypointAddress()
		if waypointAddr != nil && waypointAddr.String() == address.String() {
			return nil
		}

		log.Debugf("Refreshing services associated with waypoint %s", resourceName)
		res = associated.update(address)
	}

	return res
}

func updateWaypoint(svc *workloadapi.Service, addr *workloadapi.NetworkAddress) {
	svc.GetWaypoint().Destination = &workloadapi.GatewayAddress_Address{
		Address: addr,
	}
}
