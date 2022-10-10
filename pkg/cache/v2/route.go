/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2022-02-15
 */

package cache_v2

import (
	core_v2 "openeuler.io/mesh/api/v2/core"
	route_v2 "openeuler.io/mesh/api/v2/route"
	maps_v2 "openeuler.io/mesh/pkg/cache/v2/maps"
)

type ApiRouteConfigurationCache map[string]*route_v2.RouteConfiguration

func NewApiRouteConfigurationCache() ApiRouteConfigurationCache {
	return make(ApiRouteConfigurationCache)
}

func (cache ApiRouteConfigurationCache) StatusFlush(status core_v2.ApiStatus) int {
	var (
		err error
		num int
	)

	for _, route := range cache {
		if route.GetApiStatus() != status {
			continue
		}

		switch route.GetApiStatus() {
		case core_v2.ApiStatus_UPDATE:
			err = maps_v2.RouteConfigUpdate(route.GetName(), route)
		case core_v2.ApiStatus_DELETE:
			err = maps_v2.RouteConfigDelete(route.GetName())
		}

		if err != nil {
			log.Errorln(err)
		}
		num++
	}

	if status == core_v2.ApiStatus_DELETE {
		cache.StatusDelete(status)
	}

	return num
}

func (cache ApiRouteConfigurationCache) StatusDelete(flag core_v2.ApiStatus) {
	for name, route := range cache {
		if route.GetApiStatus() == flag {
			delete(cache, name)
		}
	}
}

func (cache ApiRouteConfigurationCache) StatusReset(old, new core_v2.ApiStatus) {
	for _, route := range cache {
		if route.GetApiStatus() == old {
			route.ApiStatus = new
		}
	}
}

func (cache ApiRouteConfigurationCache) StatusLookup() []*route_v2.RouteConfiguration {
	var err error
	var mapCache []*route_v2.RouteConfiguration

	for name, route := range cache {
		tmp := &route_v2.RouteConfiguration{}
		if err = maps_v2.RouteConfigLookup(name, tmp); err != nil {
			log.Errorf("RouteConfigLookup failed, %s", name)
			continue
		}

		tmp.ApiStatus = route.ApiStatus
		mapCache = append(mapCache, tmp)
	}

	return mapCache
}

func (cache ApiRouteConfigurationCache) StatusRead() []*route_v2.RouteConfiguration {
	var mapCache []*route_v2.RouteConfiguration

	for _, route := range cache {
		mapCache = append(mapCache, route)
	}
	return mapCache
}
