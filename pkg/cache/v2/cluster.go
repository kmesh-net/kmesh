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

 * Author: LemmyHuang
 * Create: 2022-02-15
 */

package cache_v2

import (
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"

	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	maps_v2 "kmesh.net/kmesh/pkg/cache/v2/maps"
)

type ClusterCache struct {
	mutex           sync.RWMutex
	apiClusterCache apiClusterCache
	// resourceHash[0]:cds  resourceHash[1]:eds
	resourceHash map[string][2]uint64
}

func NewClusterCache() ClusterCache {
	return ClusterCache{
		apiClusterCache: newApiClusterCache(),
		resourceHash:    make(map[string][2]uint64),
	}
}

type apiClusterCache map[string]*cluster_v2.Cluster

func newApiClusterCache() apiClusterCache {
	return make(apiClusterCache)
}

func (cache *ClusterCache) GetResourceNames() sets.Set[string] {
	out := sets.New[string]()
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	for key := range cache.apiClusterCache {
		out.Insert(key)
	}
	return out
}

func (cache *ClusterCache) GetApiCluster(key string) *cluster_v2.Cluster {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	return cache.apiClusterCache[key]
}

func (cache *ClusterCache) SetApiCluster(key string, value *cluster_v2.Cluster) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.apiClusterCache[key] = value
}

func (cache *ClusterCache) UpdateApiClusterStatus(key string, status core_v2.ApiStatus) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if cluster := cache.apiClusterCache[key]; cluster != nil {
		cluster.ApiStatus = status
	}
}

func (cache *ClusterCache) GetCdsHash(key string) uint64 {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	return cache.resourceHash[key][0]
}

func (cache *ClusterCache) SetCdsHash(key string, value uint64) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.resourceHash[key] = [2]uint64{value, cache.resourceHash[key][1]}
}

func (cache *ClusterCache) GetEdsHash(key string) uint64 {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	return cache.resourceHash[key][1]
}

func (cache *ClusterCache) SetEdsHash(key string, value uint64) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.resourceHash[key] = [2]uint64{cache.resourceHash[key][0], value}
}

// Flush flushes the cluster to bpf map.
func (cache *ClusterCache) Flush() {
	for name, cluster := range cache.apiClusterCache {
		switch cluster.GetApiStatus() {
		case core_v2.ApiStatus_UPDATE:
			cluster.ApiStatus = core_v2.ApiStatus_NONE
		case core_v2.ApiStatus_DELETE:
			delete(cache.apiClusterCache, name)
			delete(cache.resourceHash, name)
		}
	}
}

var cacheDeepCopy *ClusterCache

func (cache *ClusterCache) BpfMapFlush() {
	for {
		// if cacheDeepCopy not equal cache, need flush
		if !clusterEqualFromHash(cacheDeepCopy, cache) {
			cacheDeepCopy = cache.DeepCopy()
			for name, cluster := range cacheDeepCopy.apiClusterCache {
				switch cluster.GetApiStatus() {
				case core_v2.ApiStatus_UPDATE:
					if err := maps_v2.ClusterUpdate(name, cluster); err != nil {
						log.Errorf("cluster %s update failed: %v", name, err)
						// Rollback on update failure
						cache.apiClusterCache = cacheDeepCopy.apiClusterCache
						cache.resourceHash = cacheDeepCopy.resourceHash
					} else {
						cluster.ApiStatus = core_v2.ApiStatus_NONE
					}
				case core_v2.ApiStatus_DELETE:
					if err := maps_v2.ClusterDelete(name); err != nil {
						log.Errorf("cluster %s delete failed: %v", name, err)
						cache.apiClusterCache = cacheDeepCopy.apiClusterCache
						cache.resourceHash = cacheDeepCopy.resourceHash
					}
				}
			}
		} else {
			break
		}
	}
}

func clusterEqualFromHash(cache1, cache2 *ClusterCache) bool {
	if (cache1 == nil && cache2 != nil) || (cache2 == nil && cache1 != nil) {
		return false
	}

	if len(cache1.resourceHash) != len(cache2.resourceHash) {
		return false
	}

	for k, v := range cache1.resourceHash {
		if valueInCache2, ok := cache2.resourceHash[k]; !ok || v != valueInCache2 {
			return false
		}
	}

	return true
}

func (cache *ClusterCache) DeepCopy() *ClusterCache {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	cacheCopy := NewClusterCache()
	cacheCopy.resourceHash = cache.resourceHash
	cacheCopy.apiClusterCache = cache.apiClusterCache

	return &cacheCopy
}

func (cache *ClusterCache) StatusLookup() []*cluster_v2.Cluster {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	clusters := make([]*cluster_v2.Cluster, 0, len(cache.apiClusterCache))
	for name, c := range cache.apiClusterCache {
		tmp := &cluster_v2.Cluster{}
		if err := maps_v2.ClusterLookup(name, tmp); err != nil {
			log.Errorf("ClusterLookup failed, %s", name)
			continue
		}

		tmp.ApiStatus = c.ApiStatus
		clusters = append(clusters, tmp)
	}

	return clusters
}

func (cache *ClusterCache) StatusRead() []*cluster_v2.Cluster {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	clusters := make([]*cluster_v2.Cluster, 0, len(cache.apiClusterCache))
	for _, c := range cache.apiClusterCache {
		clusters = append(clusters, c)
	}
	return clusters
}
