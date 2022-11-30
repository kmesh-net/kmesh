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

	cluster_v2 "openeuler.io/mesh/api/v2/cluster"
	core_v2 "openeuler.io/mesh/api/v2/core"
	maps_v2 "openeuler.io/mesh/pkg/cache/v2/maps"
)

var RWCluster sync.RWMutex

type ApiClusterCache map[string]*cluster_v2.Cluster

func NewApiClusterCache() ApiClusterCache {
	return make(ApiClusterCache)
}

func (cache ApiClusterCache) StatusFlush(status core_v2.ApiStatus) int {
	var (
		err error
		num int
	)

	RWCluster.Lock()
	for _, cluster := range cache {
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

func (cache ApiClusterCache) StatusDelete(status core_v2.ApiStatus) {
	for name, cluster := range cache {
		if cluster.GetApiStatus() == status {
			delete(cache, name)
		}
	}
}

func (cache ApiClusterCache) StatusReset(old, new core_v2.ApiStatus) {
	for _, cluster := range cache {
		if cluster.GetApiStatus() == old {
			cluster.ApiStatus = new
		}
	}
}

func (cache ApiClusterCache) StatusLookup() []*cluster_v2.Cluster {
	var err error
	var mapCache []*cluster_v2.Cluster

	RWCluster.RLock()

	for name, route := range cache {
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

func (cache ApiClusterCache) StatusRead() []*cluster_v2.Cluster {
	var mapCache []*cluster_v2.Cluster

	for _, route := range cache {
		mapCache = append(mapCache, route)
	}
	return mapCache
}
