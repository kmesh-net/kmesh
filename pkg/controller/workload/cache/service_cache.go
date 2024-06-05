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

package cache

import (
	"sync"

	"kmesh.net/kmesh/api/v2/workloadapi"
)

type ServiceCache interface {
	List() []*workloadapi.Service
	AddOrUpdateService(svc *workloadapi.Service)
	DeleteService(resourceName string)
}

type serviceCache struct {
	mutex sync.RWMutex
	// keyed by namespace/hostname->service
	servicesByResourceName map[string]*workloadapi.Service
}

func NewServiceCache() *serviceCache {
	return &serviceCache{
		servicesByResourceName: make(map[string]*workloadapi.Service),
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
