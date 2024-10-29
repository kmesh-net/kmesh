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

	"istio.io/istio/pkg/log"
	"kmesh.net/kmesh/api/v2/workloadapi"
)

type ServiceCache interface {
	List() []*workloadapi.Service
	AddOrUpdateService(svc *workloadapi.Service)
	DeleteService(resourceName string)
	GetService(resourceName string) *workloadapi.Service
	HandleWaypoint(svc *workloadapi.Service) []*workloadapi.Service
}

type serviceCache struct {
	mutex sync.RWMutex
	// keyed by namespace/hostname->service
	servicesByResourceName map[string]*workloadapi.Service

	// NOTE: The following data structure is used to change the waypoint
	// address of type hostname in the service to type ip address.
	waypointToServices map[string]map[string]*workloadapi.Service
	waypointToAddress  map[string]*workloadapi.NetworkAddress
}

func NewServiceCache() *serviceCache {
	return &serviceCache{
		servicesByResourceName: make(map[string]*workloadapi.Service),
		waypointToServices:     make(map[string]map[string]*workloadapi.Service),
		waypointToAddress:      make(map[string]*workloadapi.NetworkAddress),
	}
}

func (s *serviceCache) AddOrUpdateService(svc *workloadapi.Service) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.servicesByResourceName[svc.ResourceName()] = svc
}

func (s *serviceCache) DeleteService(resourceName string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.servicesByResourceName, resourceName)
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

// handleWaypoint is used to process a service. If it is a newly added waypoint service, it returns
// a series of services that need to be updated whose hostname type waypoint address can be converted
// to IP address type. If it is a service whose waypoint address is waiting to be converted, it is added
// to the association list of the corresponding waypoint, If it can be converted, it is converted directly,
// otherwise it waits for the arrival of the waypoint.
func (s *serviceCache) HandleWaypoint(svc *workloadapi.Service) []*workloadapi.Service {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(svc.GetAddresses()) == 0 {
		return nil
	}
	address := svc.GetAddresses()[0]
	resourceName := svc.ResourceName()

	res := []*workloadapi.Service{}
	if addr, ok := s.waypointToAddress[resourceName]; ok {
		// If this svc is a waypoint service, may need updating.
		log.Infof("--- Update waypoint %s", resourceName)
		if addr != nil && addr.String() == address.String() {
			return nil
		}
		s.waypointToAddress[resourceName] = address
		for _, svc := range s.waypointToServices[resourceName] {
			s.updateWaypoint(svc, addr)
			res = append(res, svc)
		}
	}

	if svc.GetWaypoint() == nil || svc.GetWaypoint().GetAddress() != nil {
		return res
	}

	// If this is a svc with hostname waypoint.
	hostname := svc.GetWaypoint().GetHostname()
	resourceName = hostname.GetNamespace() + "/" + hostname.GetHostname()

	log.Infof("--- Update svc %s with waypoint %s", svc.ResourceName(), resourceName)
	if addr, ok := s.waypointToAddress[resourceName]; ok {
		// The service corresponding to the waypoint has been found.
		s.updateWaypoint(svc, addr)
	} else {
		// Try to find the waypoint service from the cache.
		waypointService := s.servicesByResourceName[resourceName]
		if waypointService == nil || len(waypointService.GetAddresses()) == 0 {
			s.waypointToAddress[resourceName] = nil
		} else {
			s.waypointToAddress[resourceName] = waypointService.GetAddresses()[0]
			s.updateWaypoint(svc, waypointService.GetAddresses()[0])
		}
		s.waypointToServices[resourceName] = make(map[string]*workloadapi.Service)
	}
	// Anyway, add svc to the association list.
	s.waypointToServices[resourceName][svc.ResourceName()] = svc

	return res
}

func (s *serviceCache) updateWaypoint(svc *workloadapi.Service, addr *workloadapi.NetworkAddress) {
	svc.GetWaypoint().Destination = &workloadapi.GatewayAddress_Address{
		Address: addr,
	}
}
