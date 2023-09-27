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

	cluster_v2 "oncn.io/mesh/api/v2/cluster"
	core_v2 "oncn.io/mesh/api/v2/core"
	maps_v2 "oncn.io/mesh/pkg/cache/v2/maps"
)

var RWCluster sync.RWMutex

type ClusterCache struct {
	apiClusterCache apiClusterCache
	// resourceCache[0]:cds  resourceCache[1]:eds
	resourceCache map[string][2]string
}

func NewClusterCache() ClusterCache {
	return ClusterCache{
		apiClusterCache: newApiClusterCache(),
		resourceCache:   make(map[string][2]string),
	}
}

type apiClusterCache map[string]*cluster_v2.Cluster

func newApiClusterCache() apiClusterCache {
	return make(apiClusterCache)
}

func (cache *ClusterCache) GetApiClusterCache(key string) *cluster_v2.Cluster {
	return cache.apiClusterCache[key]
}

func (cache *ClusterCache) SetApiClusterCache(key string, value *cluster_v2.Cluster) {
	cache.apiClusterCache[key] = value
}

func (cache *ClusterCache) GetCdsResource(key string) string {
	return cache.resourceCache[key][0]
}

func (cache *ClusterCache) SetCdsResource(key string, value string) {
	cache.resourceCache[key] = [2]string{value, cache.resourceCache[key][1]}
}

func (cache *ClusterCache) GetEdsResource(key string) string {
	return cache.resourceCache[key][1]
}

func (cache *ClusterCache) SetEdsResource(key string, value string) {
	cache.resourceCache[key] = [2]string{cache.resourceCache[key][0], value}
}

func (cache ClusterCache) StatusFlush(status core_v2.ApiStatus) int {
	var (
		err error
		num int
	)

	RWCluster.Lock()
	for _, cluster := range cache.apiClusterCache {
		if cluster.GetApiStatus() != status {
			continue
		}

		switch cluster.GetApiStatus() {
		case core_v2.ApiStatus_UPDATE:
			err = maps_v2.ClusterUpdate(cluster.GetName(), cluster)
		case core_v2.ApiStatus_DELETE:
			err = maps_v2.ClusterDelete(cluster.GetName())
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

	defer RWCluster.Unlock()

	return num
}

func (cache ClusterCache) StatusDelete(status core_v2.ApiStatus) {
	for name, cluster := range cache.apiClusterCache {
		if cluster.GetApiStatus() == status {
			delete(cache.apiClusterCache, name)
			delete(cache.resourceCache, name)
		}
	}
}

func (cache ClusterCache) StatusReset(old, new core_v2.ApiStatus) {
	for _, cluster := range cache.apiClusterCache {
		if cluster.GetApiStatus() == old {
			cluster.ApiStatus = new
		}
	}
}

func (cache ClusterCache) StatusLookup() []*cluster_v2.Cluster {
	var err error
	var mapCache []*cluster_v2.Cluster

	RWCluster.RLock()

	for name, route := range cache.apiClusterCache {
		tmp := &cluster_v2.Cluster{}
		if err = maps_v2.ClusterLookup(name, tmp); err != nil {
			log.Errorf("ClusterLookup failed, %s", name)
			continue
		}

		tmp.ApiStatus = route.ApiStatus
		mapCache = append(mapCache, tmp)
	}
	defer RWCluster.RUnlock()

	return mapCache
}

func (cache ClusterCache) StatusRead() []*cluster_v2.Cluster {
	var mapCache []*cluster_v2.Cluster

	for _, route := range cache.apiClusterCache {
		mapCache = append(mapCache, route)
	}
	return mapCache
}
