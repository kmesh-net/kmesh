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

// EndpointEntry holds the data needed to restore a single endpoint into the
// in-memory cache. ServiceId, Prio and BackendIndex come from the BPF
// endpoint map key; WorkloadId is the BackendUid stored in the value.
type EndpointEntry struct {
	ServiceId    uint32
	Prio         uint32
	BackendIndex uint32
	WorkloadId   uint32
}

// TODO: use `EndpointKey` struct
type Endpoint struct {
	ServiceId    uint32
	Prio         uint32
	BackendIndex uint32
}

type EndpointCache interface {
	List(uint32) map[uint32]Endpoint // Endpoint slice by ServiceId
	AddEndpointToService(ep Endpoint, serviceID uint32)
	// DeleteEndpoint delete a endpoint regardless of the priority
	DeleteEndpoint(workloadID, serviceID uint32)
	// DeleteEndpointWithPriority delete a endpoint with given priority
	DeleteEndpointWithPriority(serviceID, workloadID, prio uint32)
	// DeleteEndpointByServiceId delete all endpoints belong to a given service
	DeleteEndpointByServiceId(uint32)
	// RestoreEndpoint rebuilds the in-memory cache from persisted BPF map
	// entries on a warm restart.
	RestoreEndpoint(entries []EndpointEntry)
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

func (s *endpointCache) DeleteEndpoint(serviceID, workloadID uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.endpointsByServiceId[serviceID], workloadID)
}

func (s *endpointCache) DeleteEndpointWithPriority(serviceID, workloadID, prio uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.endpointsByServiceId[serviceID] != nil {
		if ep, ok := s.endpointsByServiceId[serviceID][workloadID]; ok && ep.Prio == prio {
			delete(s.endpointsByServiceId[serviceID], workloadID)
		}
	}
}

func (s *endpointCache) DeleteEndpointByServiceId(serviceId uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.endpointsByServiceId, serviceId)
}

// RestoreEndpoint rebuilds the in-memory endpoint cache from persisted BPF
// endpoint map entries after a warm restart. The caller is responsible for
// supplying the entries (typically obtained by iterating the BPF map).
func (s *endpointCache) RestoreEndpoint(entries []EndpointEntry) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, entry := range entries {
		ep := Endpoint{
			ServiceId:    entry.ServiceId,
			Prio:         entry.Prio,
			BackendIndex: entry.BackendIndex,
		}
		if s.endpointsByServiceId[entry.ServiceId] == nil {
			s.endpointsByServiceId[entry.ServiceId] = make(map[uint32]Endpoint)
		}
		s.endpointsByServiceId[entry.ServiceId][entry.WorkloadId] = ep
	}
}

func (s *endpointCache) List(serviceId uint32) map[uint32]Endpoint {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.endpointsByServiceId[serviceId]
}
