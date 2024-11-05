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

 * Author: LemmyHuang
 * Create: 2022-02-15
 */

package cache_v2

import (
	"sync"

	"github.com/cilium/ebpf"
	"k8s.io/apimachinery/pkg/util/sets"

	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	bpfads "kmesh.net/kmesh/pkg/bpf/ads"
	maps_v2 "kmesh.net/kmesh/pkg/cache/v2/maps"
	"kmesh.net/kmesh/pkg/consistenthash/maglev"
	"kmesh.net/kmesh/pkg/utils"
)

type ClusterStatsKey struct {
	NetnsCookie uint64
	ClusterId   uint32
}

type ClusterStatsValue struct {
	ActiveConnections uint32
}

type ClusterCache struct {
	mutex           sync.RWMutex
	apiClusterCache apiClusterCache
	// resourceHash[0]:cds  resourceHash[1]:eds
	resourceHash    map[string][2]uint64
	hashName        *utils.HashName
	clusterStatsMap *ebpf.Map
}

func NewClusterCache(bpfAds *bpfads.BpfAds, hashName *utils.HashName) ClusterCache {
	var clusterStatsMap *ebpf.Map
	if bpfAds != nil {
		clusterStatsMap = bpfAds.GetClusterStatsMap()
	}
	return ClusterCache{
		apiClusterCache: newApiClusterCache(),
		resourceHash:    make(map[string][2]uint64),
		hashName:        hashName,
		clusterStatsMap: clusterStatsMap,
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

func (cache *ClusterCache) UpdateApiClusterIfExists(key string, value *cluster_v2.Cluster) bool {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if cache.apiClusterCache[key] == nil {
		return false
	}
	cache.apiClusterCache[key] = value
	return true
}

func (cache *ClusterCache) UpdateApiClusterStatus(key string, status core_v2.ApiStatus) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if cluster := cache.apiClusterCache[key]; cluster != nil {
		cluster.ApiStatus = status
	}
}

func (cache *ClusterCache) GetApiClusterStatus(key string) core_v2.ApiStatus {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	if cluster := cache.apiClusterCache[key]; cluster != nil {
		return cluster.ApiStatus
	}
	return core_v2.ApiStatus_NONE
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

func (cache *ClusterCache) clearClusterStats(clusterName string) {
	if cache.clusterStatsMap == nil {
		return
	}
	clusterId := cache.hashName.StrToNum(clusterName)
	var key ClusterStatsKey
	var value ClusterStatsValue
	var keysToDelete []ClusterStatsKey
	it := cache.clusterStatsMap.Iterate()

	for it.Next(&key, &value) {
		if key.ClusterId == clusterId {
			keysToDelete = append(keysToDelete, key)
		}
	}
	if len(keysToDelete) > 0 {
		log.Debugf("remove cluster stats: %v", keysToDelete)
		_, err := cache.clusterStatsMap.BatchDelete(keysToDelete, nil)
		if err != nil {
			log.Errorf("failed to remove cluster stats: %v", err)
		}
	}

	if err := it.Err(); err != nil {
		log.Errorf("delete iteration error: %s", err)
	}
}

// Flush flushes the cluster to bpf map.
func (cache *ClusterCache) Flush() {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	for name, cluster := range cache.apiClusterCache {
		if cluster.GetApiStatus() == core_v2.ApiStatus_UPDATE {
			cluster.Id = cache.hashName.StrToNum(name)
			err := maps_v2.ClusterUpdate(name, cluster)
			if cluster.GetLbPolicy() == cluster_v2.Cluster_MAGLEV {
				// create consistent lb here and update table to bpf map
				if err := maglev.CreateLB(cluster); err != nil {
					log.Errorf("maglev lb update %v cluster failed: %v", name, err)
				}
			}
			if err == nil {
				// reset api status after successfully updated
				cluster.ApiStatus = core_v2.ApiStatus_NONE
			} else {
				log.Errorf("cluster %s %s flush failed: %v", name, cluster.ApiStatus, err)
			}
		} else if cluster.GetApiStatus() == core_v2.ApiStatus_DELETE {
			cache.clearClusterStats(name)
			err := maps_v2.ClusterDelete(name)
			if err == nil {
				delete(cache.apiClusterCache, name)
				delete(cache.resourceHash, name)
				cache.hashName.Delete(name)
			} else {
				log.Errorf("cluster %s delete failed: %v", name, err)
			}
		}
	}
}

// Delete delete the clusters marked Delete status.
func (cache *ClusterCache) Delete() {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	for name, cluster := range cache.apiClusterCache {
		if cluster.GetApiStatus() == core_v2.ApiStatus_DELETE {
			err := maps_v2.ClusterDelete(name)
			if err == nil {
				delete(cache.apiClusterCache, name)
				delete(cache.resourceHash, name)
				cache.hashName.Delete(name)
			} else {
				log.Errorf("cluster %s delete failed: %v", name, err)
			}
		}
	}
}

func (cache *ClusterCache) Dump() []*cluster_v2.Cluster {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	clusters := make([]*cluster_v2.Cluster, 0, len(cache.apiClusterCache))
	for _, c := range cache.apiClusterCache {
		clusters = append(clusters, c)
	}
	return clusters
}

func (cache *ClusterCache) GetClusterHashPtr() *map[string][2]uint64 {
	return &cache.resourceHash
}
