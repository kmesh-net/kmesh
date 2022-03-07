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
	listener_v2 "openeuler.io/mesh/api/v2/listener"
	maps_v2 "openeuler.io/mesh/pkg/cache/v2/maps"
	"openeuler.io/mesh/pkg/logger"
)

var (
	log = logger.NewLoggerField("cache/v2")
)

type ApiListenerCache map[string]*listener_v2.Listener

func NewApiListenerCache() ApiListenerCache {
	return make(ApiListenerCache)
}

func (cache ApiListenerCache) StatusFlush(status core_v2.ApiStatus) int {
	var (
		err error
		num int
	)

	for _, listener := range cache {
		if listener.GetApiStatus() != status {
			continue
		}

		switch listener.GetApiStatus() {
		case core_v2.ApiStatus_UPDATE:
			err = maps_v2.ListenerUpdate(listener.GetAddress(), listener)
		case core_v2.ApiStatus_DELETE:
			err = maps_v2.ListenerDelete(listener.GetAddress())
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

func (cache ApiListenerCache) StatusDelete(status core_v2.ApiStatus) {
	for name, listener := range cache {
		if listener.GetApiStatus() == status {
			delete(cache, name)
		}
	}
}

func (cache ApiListenerCache) StatusReset(old, new core_v2.ApiStatus) {
	for _, listener := range cache {
		if listener.GetApiStatus() == old {
			listener.ApiStatus = new
		}
	}
}

func (cache ApiListenerCache) StatusLookup() []*listener_v2.Listener {
	var err error
	var mapCache []*listener_v2.Listener

	for name, listener := range cache {
		tmp := &listener_v2.Listener{}
		if err = maps_v2.ListenerLookup(listener.GetAddress(), tmp); err != nil {
			log.Errorf("ListenerLookup failed, %s", name)
			continue
		}

		tmp.ApiStatus = listener.ApiStatus
		mapCache = append(mapCache, tmp)
	}

	return mapCache
}

func (cache ApiListenerCache) StatusRead() []*listener_v2.Listener {
	var mapCache []*listener_v2.Listener

	for _, listener := range cache {
		mapCache = append(mapCache, listener)
	}
	return mapCache
}
