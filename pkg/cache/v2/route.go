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
)

type ApiRouteConfigurationCache map[string]*route_v2.RouteConfiguration

func NewApiRouteConfigurationCache() ApiRouteConfigurationCache {
	return make(ApiRouteConfigurationCache)
}

func (cache ApiRouteConfigurationCache) packUpdate() error {
	return nil
}

func (cache ApiRouteConfigurationCache) packDelete() error {
	return nil
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
			err = cache.packUpdate()
			log.Debugf("ApiStatus_UPDATE [%s]", route.String())
		case core_v2.ApiStatus_DELETE:
			err = cache.packDelete()
			log.Debugf("ApiStatus_DELETE [%s]", route.String())
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