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
	cluster_v2 "openeuler.io/mesh/api/v2/cluster"
	core_v2 "openeuler.io/mesh/api/v2/core"
)

type ApiClusterCache map[string]*cluster_v2.Cluster

func NewApiClusterCache() ApiClusterCache {
	return make(ApiClusterCache)
}

func (cache ApiClusterCache) packUpdate() error {
	return nil
}

func (cache ApiClusterCache) packDelete() error {
	return nil
}

func (cache ApiClusterCache) StatusFlush(status core_v2.ApiStatus) int {
	var (
		err error
		num int
	)

	for _, cluster := range cache {
		if cluster.GetApiStatus() != status {
			continue
		}

		switch cluster.GetApiStatus() {
		case core_v2.ApiStatus_UPDATE:
			err = cache.packUpdate()
		case core_v2.ApiStatus_DELETE:
			err = cache.packDelete()
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
