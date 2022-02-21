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
 * Create: 2021-12-22
 */

package cache_v1

import (
	"fmt"
	"openeuler.io/mesh/api/v1/maps"
	"openeuler.io/mesh/api/v1/types"
)

type ClusterKeyAndValue struct {
	Key		types.MapKey
	Value	types.Cluster
}

func (kv *ClusterKeyAndValue) packUpdate(count CacheCount) error {
	if err := maps.ClusterUpdate(&kv.Value, &kv.Key); err != nil {
		return fmt.Errorf("update cluster failed, %v, %s", kv.Value, err)
	}

	count[kv.Key.Port] = 1
	return nil
}

func (kv *ClusterKeyAndValue) packDelete(count CacheCount) error {
	if err := maps.ClusterDelete(&kv.Value, &kv.Key); err != nil {
		return fmt.Errorf("delete cluster failed, %v, %s", kv.Key, err)
	}

	delete(count, kv.Key.Port)
	return nil
}

type ClusterCache map[ClusterKeyAndValue]CacheOptionFlag

func (cache ClusterCache) StatusFlush(flag CacheOptionFlag, count CacheCount) int {
	var err error
	var num int

	for kv, f := range cache {
		if f != flag {
			continue
		}

		switch flag {
		case CacheFlagDelete:
			err = kv.packDelete(count)
		case CacheFlagUpdate:
			err = kv.packUpdate(count)
			cache[kv] = CacheFlagNone
		default:
		}
		num++

		if err != nil {
			log.Errorln(err)
		}
	}

	if flag == CacheFlagDelete {
		cache.StatusDelete(flag)
	}

	return num
}

func (cache ClusterCache) StatusDelete(flag CacheOptionFlag) {
	for kv, f := range cache {
		if f == flag {
			delete(cache, kv)
		}
	}
}

func (cache ClusterCache) StatusReset(old, new CacheOptionFlag) {
	for kv, f := range cache {
		if f == old {
			cache[kv] = new
		}
	}
}
