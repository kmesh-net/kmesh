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
	api_v1 "openeuler.io/mesh/api/v1"
	"openeuler.io/mesh/pkg/cache/v1/maps"
	"openeuler.io/mesh/pkg/logger"
)

const (
	pkgSubsys = "cache_v2"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
)

type ListenerKeyAndValue struct {
	Key		api_v1.Address
	Value	api_v1.Listener
}

func (kv *ListenerKeyAndValue) packUpdate() error {
	if err := maps.ListenerUpdate(&kv.Value, &kv.Key); err != nil {
		return fmt.Errorf("update listener failed, %v, %s", kv.Key, err)
	}
	return nil
}

func (kv *ListenerKeyAndValue) packDelete() error {
	if err := maps.ListenerDelete(&kv.Value, &kv.Key); err != nil {
		return fmt.Errorf("delete listener failed, %v, %s", kv.Key, err)
	}
	return nil
}

type ListenerCache map[ListenerKeyAndValue]CacheOptionFlag

func (cache ListenerCache) StatusFlush(flag CacheOptionFlag) int {
	var err error
	var num int

	for kv, f := range cache {
		if f != flag {
			continue
		}

		switch flag {
		case CacheFlagDelete:
			err = kv.packDelete()
		case CacheFlagUpdate:
			err = kv.packUpdate()
		default:
		}

		if err != nil {
			log.Errorln(err)
		}
	}

	return num
}

func (cache ListenerCache) StatusDelete(flag CacheOptionFlag) {
	for kv, f := range cache {
		if f == flag {
			delete(cache, kv)
		}
	}
}

func (cache ListenerCache) StatusReset(old, new CacheOptionFlag) {
	for kv, f := range cache {
		if f == old {
			cache[kv] = new
		}
	}
}
