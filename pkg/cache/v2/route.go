/*
 * Copyright 2023 The Kmesh Authors.
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

package cache_v2

import (
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"

	core_v2 "kmesh.net/kmesh/api/v2/core"
	route_v2 "kmesh.net/kmesh/api/v2/route"
	maps_v2 "kmesh.net/kmesh/pkg/cache/v2/maps"
)

type RouteConfigCache struct {
	mutex               sync.RWMutex
	apiRouteConfigCache ApiRouteConfigurationCache
	resourceHash        map[string]uint64
}

func NewRouteConfigCache() RouteConfigCache {
	return RouteConfigCache{
		apiRouteConfigCache: newApiRouteConfigurationCache(),
		resourceHash:        make(map[string]uint64),
	}
}

type ApiRouteConfigurationCache map[string]*route_v2.RouteConfiguration

func newApiRouteConfigurationCache() ApiRouteConfigurationCache {
	return make(ApiRouteConfigurationCache)
}

func (cache *RouteConfigCache) SetApiRouteConfig(key string, value *route_v2.RouteConfiguration) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	cache.apiRouteConfigCache[key] = value
}

func (cache *RouteConfigCache) GetApiRouteConfig(key string) *route_v2.RouteConfiguration {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	return cache.apiRouteConfigCache[key]
}

func (cache *RouteConfigCache) GetResourceNames() sets.Set[string] {
	out := sets.New[string]()
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	for key := range cache.apiRouteConfigCache {
		out.Insert(key)
	}
	return out
}

func (cache *RouteConfigCache) UpdateApiRouteStatus(key string, status core_v2.ApiStatus) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if route := cache.apiRouteConfigCache[key]; route != nil {
		route.ApiStatus = status
	}
}

func (cache *RouteConfigCache) GetRdsHash(key string) uint64 {
	return cache.resourceHash[key]
}

func (cache *RouteConfigCache) SetRdsHash(key string, value uint64) {
	cache.resourceHash[key] = value
}

func (cache *RouteConfigCache) Flush() {
	var err error
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	for name, route := range cache.apiRouteConfigCache {
		switch route.GetApiStatus() {
		case core_v2.ApiStatus_UPDATE:
			err = maps_v2.RouteConfigUpdate(name, route)
			if err == nil {
				// reset api status after successfully updated
				route.ApiStatus = core_v2.ApiStatus_NONE
			}
		case core_v2.ApiStatus_DELETE:
			err = maps_v2.RouteConfigDelete(name)
			if err == nil {
				delete(cache.apiRouteConfigCache, name)
				delete(cache.resourceHash, name)
			}
		}
		if err != nil {
			log.Errorf("routeConfig %s %s flush failed: %v", name, route.ApiStatus, err)
		}
	}
}

func (cache *RouteConfigCache) DumpBpf() []*route_v2.RouteConfiguration {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	mapCache := make([]*route_v2.RouteConfiguration, 0, len(cache.apiRouteConfigCache))
	for name, route := range cache.apiRouteConfigCache {
		tmp := &route_v2.RouteConfiguration{}
		if err := maps_v2.RouteConfigLookup(name, tmp); err != nil {
			log.Errorf("RouteConfigLookup failed, %s", name)
			continue
		}

		tmp.ApiStatus = route.ApiStatus
		mapCache = append(mapCache, tmp)
	}
	return mapCache
}

func (cache *RouteConfigCache) Dump() []*route_v2.RouteConfiguration {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	mapCache := make([]*route_v2.RouteConfiguration, 0, len(cache.apiRouteConfigCache))
	for _, route := range cache.apiRouteConfigCache {
		mapCache = append(mapCache, route)
	}
	return mapCache
}
