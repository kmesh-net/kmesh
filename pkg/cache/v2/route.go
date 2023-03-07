/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
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

 * Author: LemmyHuang
 * Create: 2022-02-15
 */

package cache_v2

import (
	"sync"

	core_v2 "openeuler.io/mesh/api/v2/core"
	route_v2 "openeuler.io/mesh/api/v2/route"
	maps_v2 "openeuler.io/mesh/pkg/cache/v2/maps"
)

var RWRoute sync.RWMutex

type RouteConfigCache struct {
	apiRouteConfigCache ApiRouteConfigurationCache
	resourceCache       map[string]string
}

func NewRouteConfigCache() RouteConfigCache {
	return RouteConfigCache{
		apiRouteConfigCache: newApiRouteConfigurationCache(),
		resourceCache:       make(map[string]string),
	}
}

type ApiRouteConfigurationCache map[string]*route_v2.RouteConfiguration

func newApiRouteConfigurationCache() ApiRouteConfigurationCache {
	return make(ApiRouteConfigurationCache)
}

func (cache RouteConfigCache) SetApiRouteConfigCache(key string, value *route_v2.RouteConfiguration) {
	cache.apiRouteConfigCache[key] = value
}

func (cache RouteConfigCache) GetApiRouteConfigCache(key string) *route_v2.RouteConfiguration {
	return cache.apiRouteConfigCache[key]
}

func (cache *RouteConfigCache) GetRdsResource(key string) string {
	return cache.resourceCache[key]
}

func (cache *RouteConfigCache) SetRdsResource(key string, value string) {
	cache.resourceCache[key] = value
}

func (cache RouteConfigCache) StatusFlush(status core_v2.ApiStatus) int {
	var (
		err error
		num int
	)

	RWRoute.Lock()

	for _, route := range cache.apiRouteConfigCache {
		if route.GetApiStatus() != status {
			continue
		}

		switch route.GetApiStatus() {
		case core_v2.ApiStatus_UPDATE:
			err = maps_v2.RouteConfigUpdate(route.GetName(), route)
		case core_v2.ApiStatus_DELETE:
			err = maps_v2.RouteConfigDelete(route.GetName())
		default:
			break
		}

		if err != nil {
			log.Errorln(err)
		}
		num++
	}

	if status == core_v2.ApiStatus_DELETE {
		cache.StatusDelete(status)
	}

	defer RWRoute.Unlock()

	return num
}

func (cache RouteConfigCache) StatusDelete(flag core_v2.ApiStatus) {
	for name, route := range cache.apiRouteConfigCache {
		if route.GetApiStatus() == flag {
			delete(cache.apiRouteConfigCache, name)
			delete(cache.resourceCache, name)
		}
	}
}

func (cache RouteConfigCache) StatusReset(old, new core_v2.ApiStatus) {
	for _, route := range cache.apiRouteConfigCache {
		if route.GetApiStatus() == old {
			route.ApiStatus = new
		}
	}
}

func (cache RouteConfigCache) StatusLookup() []*route_v2.RouteConfiguration {
	var err error
	var mapCache []*route_v2.RouteConfiguration

	RWRoute.RLock()

	for name, route := range cache.apiRouteConfigCache {
		tmp := &route_v2.RouteConfiguration{}
		if err = maps_v2.RouteConfigLookup(name, tmp); err != nil {
			log.Errorf("RouteConfigLookup failed, %s", name)
			continue
		}

		tmp.ApiStatus = route.ApiStatus
		mapCache = append(mapCache, tmp)
	}

	defer RWRoute.RUnlock()

	return mapCache
}

func (cache RouteConfigCache) StatusRead() []*route_v2.RouteConfiguration {
	var mapCache []*route_v2.RouteConfiguration

	for _, route := range cache.apiRouteConfigCache {
		mapCache = append(mapCache, route)
	}
	return mapCache
}
