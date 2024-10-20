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
	List(uint32) []Endpoint // Endpoint slice by ServiceId
	AddEndpointToService(Endpoint)
	DeleteEndpoint(Endpoint)
}

type endpointCache struct {
	mutex sync.RWMutex
	// keyed by namespace/hostname->service
	endpointsByServiceId map[uint32]map[Endpoint]struct{} // we use backend
}

func NewEndpointCache() *endpointCache {
	return &endpointCache{
		endpointsByServiceId: make(map[uint32]map[Endpoint]struct{}),
	}
}

func (s *endpointCache) AddEndpointToService(ep Endpoint) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	tmp, ok := s.endpointsByServiceId[ep.ServiceId]
	if !ok {
		tmp = make(map[Endpoint]struct{})
	}
	tmp[ep] = struct{}{}
}

func (s *endpointCache) DeleteEndpoint(ep Endpoint) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.endpointsByServiceId[ep.ServiceId], ep)
}

func (s *endpointCache) RestoreEndpoint() {
	// we need update endpoint_cache after bpfcache.RestoreEndpointKeys
	// Todo
}

func (s *endpointCache) List(serviceId uint32) []Endpoint {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	out := make([]Endpoint, 0, len(s.endpointsByServiceId[serviceId]))
	for ep := range s.endpointsByServiceId[serviceId] {
		out = append(out, ep)
	}

	return out
}
