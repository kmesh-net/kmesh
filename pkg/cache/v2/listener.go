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
	"sync"

	core_v2 "openeuler.io/mesh/api/v2/core"
	listener_v2 "openeuler.io/mesh/api/v2/listener"
	maps_v2 "openeuler.io/mesh/pkg/cache/v2/maps"
	"openeuler.io/mesh/pkg/logger"
)

var RWListener sync.RWMutex

var (
	log = logger.NewLoggerField("cache/v2")
)

type ListenerCache struct{
	apiListenerCache apiListenerCache
	resourceCache   map[string]string
}

func NewListenerCache() ListenerCache {
	return ListenerCache {
		apiListenerCache: NewApiListenerCache(),
		resourceCache: make(map[string]string),
	}
}

type apiListenerCache map[string]*listener_v2.Listener

func NewApiListenerCache() apiListenerCache {
	return make(apiListenerCache)
}

func (cache *ListenerCache)GetApiListenerCache(key string) *listener_v2.Listener {
	return cache.apiListenerCache[key]
}

func (cache *ListenerCache)SetApiListenerCache(key string, value *listener_v2.Listener) {
	cache.apiListenerCache[key] = value
}

func (cache *ListenerCache)GetLdsResource(key string) string {
	return cache.resourceCache[key]
}

func (cache *ListenerCache)SetLdsResource(key string, value string) {
	cache.resourceCache[key] = value
}

func (cache ListenerCache) StatusFlush(status core_v2.ApiStatus) int {
	var (
		err error
		num int
	)

	RWListener.Lock()

	for _, listener := range cache.apiListenerCache {
		if listener.GetApiStatus() != status {
			continue
		}

		switch listener.GetApiStatus() {
		case core_v2.ApiStatus_UPDATE:
			err = maps_v2.ListenerUpdate(listener.GetAddress(), listener)
		case core_v2.ApiStatus_DELETE:
			err = maps_v2.ListenerDelete(listener.GetAddress())
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

	defer RWListener.Unlock()

	return num
}

func (cache ListenerCache) StatusDelete(status core_v2.ApiStatus) {
	for name, listener := range cache.apiListenerCache {
		if listener.GetApiStatus() == status {
			delete(cache.apiListenerCache, name)
			delete(cache.resourceCache, name)
		}
	}
}

func (cache ListenerCache) StatusReset(old, new core_v2.ApiStatus) {
	for _, listener := range cache.apiListenerCache {
		if listener.GetApiStatus() == old {
			listener.ApiStatus = new
		}
	}
}

func (cache ListenerCache) StatusLookup() []*listener_v2.Listener {
	var err error
	var mapCache []*listener_v2.Listener

	RWListener.RLock()

	for name, listener := range cache.apiListenerCache {
		tmp := &listener_v2.Listener{}
		if err = maps_v2.ListenerLookup(listener.GetAddress(), tmp); err != nil {
			log.Errorf("ListenerLookup failed, %s", name)
			continue
		}

		tmp.ApiStatus = listener.ApiStatus
		mapCache = append(mapCache, tmp)
	}

	defer RWListener.RUnlock()

	return mapCache
}

func (cache ListenerCache) StatusRead() []*listener_v2.Listener {
	var mapCache []*listener_v2.Listener

	for _, listener := range cache.apiListenerCache {
		mapCache = append(mapCache, listener)
	}
	return mapCache
}
