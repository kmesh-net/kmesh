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
	maps_v1 "openeuler.io/mesh/pkg/cache/v1/maps"
)

const (
	CacheFlagNone   CacheOptionFlag = 0x00
	CacheFlagDelete CacheOptionFlag = 0x01
	CacheFlagUpdate CacheOptionFlag = 0x02
	CacheFlagAll    CacheOptionFlag = CacheFlagDelete & CacheFlagUpdate
)

type CacheOptionFlag uint
type CacheCount map[uint32]uint32                   // k = port
type AddressToMapKey map[api_v1.Address]api_v1.MapKey // k = port

type EndpointKeyAndValue struct {
	Key		api_v1.MapKey
	Value	api_v1.Endpoint
}

func (kv *EndpointKeyAndValue) packUpdate(count CacheCount, addrToKey AddressToMapKey) error {
	kv.Key.Index = count[kv.Key.Port]

	if err := maps_v1.EndpointUpdate(&kv.Key, &kv.Value); err != nil {
		return fmt.Errorf("update endpoint failed, %v, %s", kv.Key, err)
	}

	// update count
	count[kv.Key.Port]++
	addrToKey[kv.Value.Address] = kv.Key

	lb := api_v1.Loadbalance{}
	lb.MapKey = kv.Key
	if err := maps_v1.LoadbalanceUpdate(&kv.Key, &lb); err != nil {
		kv.packDelete(count, addrToKey)
		return fmt.Errorf("update loadbalance failed, %v, %s", kv.Key, err)
	}

	return nil
}

func (kv *EndpointKeyAndValue) packDelete(count CacheCount, addrToKey AddressToMapKey) error {
	lb := api_v1.Loadbalance{}
	mapKey := addrToKey[kv.Value.Address]

	kv.Key.Index = mapKey.Index
	if kv.Key != mapKey {
		return fmt.Errorf("delete endpoint using invalid key, %v != %v", kv.Key, mapKey)
	}

	mapKeyTail := mapKey
	mapKeyTail.Index = count[mapKey.Port] - 1

	if mapKey != mapKeyTail {
		if err := maps_v1.EndpointLookup(&mapKeyTail, &kv.Value); err == nil {
			maps_v1.EndpointUpdate(&mapKey, &kv.Value)
		}
		if err := maps_v1.LoadbalanceLookup(&mapKeyTail, &lb); err == nil {
			maps_v1.LoadbalanceUpdate(&mapKey, &lb)
		}
	}
	maps_v1.EndpointDelete(&mapKeyTail)
	maps_v1.LoadbalanceDelete(&mapKeyTail)

	// update count
	delete(addrToKey, kv.Value.Address)
	count[kv.Key.Port]--
	if count[kv.Key.Port] <= 0 {
		delete(count, kv.Key.Port)
	}

	return nil
}

type EndpointCache map[EndpointKeyAndValue]CacheOptionFlag

func (cache EndpointCache) StatusFlush(flag CacheOptionFlag, count CacheCount, addrToKey AddressToMapKey) int {
	var err error
	var num int

	for kv, f := range cache {
		if f != flag {
			continue
		}

		switch flag {
		case CacheFlagDelete:
			err = kv.packDelete(count, addrToKey)
		case CacheFlagUpdate:
			err = kv.packUpdate(count, addrToKey)
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

func (cache EndpointCache) StatusDelete(flag CacheOptionFlag) {
	for kv, f := range cache {
		if f == flag {
			delete(cache, kv)
		}
	}
}

func (cache EndpointCache) StatusReset(old, new CacheOptionFlag) {
	for kv, f := range cache {
		if f == old {
			cache[kv] = new
		}
	}
}
