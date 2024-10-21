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
)

type Endpoint struct {
	ServiceId    uint32
	Prio         uint32
	BackendIndex uint32
}

type EndpointCache interface {
	List(uint32) map[uint32]Endpoint // Endpoint slice by ServiceId
	AddEndpointToService(Endpoint, uint32)
	DeleteEndpoint(Endpoint, uint32)
	DeleteEndpointByServiceId(uint32)
}

type endpointCache struct {
	mutex sync.RWMutex
	// map[serviceId][workloadId]
	endpointsByServiceId map[uint32]map[uint32]Endpoint
}

func NewEndpointCache() *endpointCache {
	return &endpointCache{
		endpointsByServiceId: make(map[uint32]map[uint32]Endpoint),
	}
}

func (s *endpointCache) AddEndpointToService(ep Endpoint, workloadId uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	_, ok := s.endpointsByServiceId[ep.ServiceId]
	if !ok {
		s.endpointsByServiceId[ep.ServiceId] = make(map[uint32]Endpoint)
	}
	s.endpointsByServiceId[ep.ServiceId][workloadId] = ep
}

func (s *endpointCache) DeleteEndpoint(ep Endpoint, workloadId uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.endpointsByServiceId[ep.ServiceId], workloadId)
}

func (s *endpointCache) DeleteEndpointByServiceId(serviceId uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.endpointsByServiceId, serviceId)
}

func (s *endpointCache) RestoreEndpoint() {
	// we need update endpoint_cache after bpfcache.RestoreEndpointKeys
	// Todo
}

func (s *endpointCache) List(serviceId uint32) map[uint32]Endpoint {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.endpointsByServiceId[serviceId]
}
