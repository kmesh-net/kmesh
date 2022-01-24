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

package api

import (
	"fmt"
	"openeuler.io/mesh/pkg/api/types"
)

type ListenerKeyAndValue struct {
	Key		types.Address
	Value	types.Listener
}

func (kv *ListenerKeyAndValue) packUpdate() error {
	if err := kv.Value.Update(&kv.Key); err != nil {
		return fmt.Errorf("update listener failed, %v, %s", kv.Key, err)
	}
	return nil
}

func (kv *ListenerKeyAndValue) packDelete() error {
	if err := kv.Value.Delete(&kv.Key); err != nil {
		return fmt.Errorf("delete listener failed, %v, %s", kv.Key, err)
	}
	return nil
}

type ListenerCache map[ListenerKeyAndValue]CacheOptionFlag

func (cache ListenerCache) Flush(flag CacheOptionFlag) int {
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

func (cache ListenerCache) DeleteFlag(flag CacheOptionFlag) {
	for kv, f := range cache {
		if f == flag {
			delete(cache, kv)
		}
	}
}

func (cache ListenerCache) ResetFlag(old, new CacheOptionFlag) {
	for kv, f := range cache {
		if f == old {
			cache[kv] = new
		}
	}
}
