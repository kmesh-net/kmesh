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
	"net/netip"
	"sync"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("cache")

type ServiceCache interface {
	List() []*workloadapi.Service
	AddOrUpdateService(svc *workloadapi.Service)
	DeleteService(resourceName string)
	GetService(resourceName string) *workloadapi.Service
	GetServiceByAddr(address NetworkAddress) *workloadapi.Service
}

var _ ServiceCache = &serviceCache{}

type serviceCache struct {
	mutex sync.RWMutex
	// keyed by namespace/hostname->service
	servicesByResourceName map[string]*workloadapi.Service
	servicesByAddr         map[NetworkAddress]*workloadapi.Service
}

func NewServiceCache() *serviceCache {
	return &serviceCache{
		servicesByResourceName: make(map[string]*workloadapi.Service),
		servicesByAddr:         make(map[NetworkAddress]*workloadapi.Service),
	}
}

func (s *serviceCache) GetServiceByAddr(address NetworkAddress) *workloadapi.Service {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.servicesByAddr[address]
}

func (s *serviceCache) AddOrUpdateService(svc *workloadapi.Service) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	resourceName := svc.ResourceName()

	s.servicesByResourceName[resourceName] = svc
	for _, addr := range svc.GetAddresses() {
		addrStr, _ := netip.AddrFromSlice(addr.GetAddress())
		networkAddress := composeNetworkAddress(addr.GetNetwork(), addrStr)
		s.servicesByAddr[networkAddress] = svc
	}
}

func (s *serviceCache) DeleteService(resourceName string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	svc, ok := s.servicesByResourceName[resourceName]
	if !ok {
		return
	}

	for _, addr := range svc.GetAddresses() {
		addrStr, _ := netip.AddrFromSlice(addr.GetAddress())
		networkAddress := composeNetworkAddress(addr.GetNetwork(), addrStr)
		s.deleteAddr(networkAddress, svc)
	}

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

func (s *serviceCache) deleteAddr(addr NetworkAddress, svc *workloadapi.Service) {
	if service, ok := s.servicesByAddr[addr]; ok {
		if service.GetNamespace() == svc.GetNamespace() && service.GetName() == svc.GetName() {
			// NOTE: If the associated service is updated, we can no longer delete it.
			// Ref: https://github.com/kmesh-net/kmesh/issues/1352
			delete(s.servicesByAddr, addr)
		}
	}
}
