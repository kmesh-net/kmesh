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
	core_v2 "openeuler.io/mesh/api/v2/core"
	listener_v2 "openeuler.io/mesh/api/v2/listener"
	"openeuler.io/mesh/pkg/logger"
)

const (
	pkgSubsys = "cache_v2"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
)

type ApiListenerCache map[string]*listener_v2.Listener

func NewApiListenerCache() ApiListenerCache {
	return make(ApiListenerCache)
}

func (cache ApiListenerCache) packUpdate() error {
	return nil
}

func (cache ApiListenerCache) packDelete() error {
	return nil
}

func (cache ApiListenerCache) StatusFlush(status core_v2.ApiStatus) int {
	var (
		err error
		num int
	)

	for _, listener := range cache {
		if listener.GetApiStatus() != status {
			continue
		}

		switch listener.GetApiStatus() {
		case core_v2.ApiStatus_UPDATE:
			err = cache.packUpdate()
			log.Debugf("ApiStatus_UPDATE [%s]", listener.String())
		case core_v2.ApiStatus_DELETE:
			err = cache.packDelete()
			log.Debugf("ApiStatus_DELETE [%s]", listener.String())
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

func (cache ApiListenerCache) StatusDelete(status core_v2.ApiStatus) {
	for name, listener := range cache {
		if listener.GetApiStatus() == status {
			delete(cache, name)
		}
	}
}

func (cache ApiListenerCache) StatusReset(old, new core_v2.ApiStatus) {
	for _, listener := range cache {
		if listener.GetApiStatus() == old {
			listener.ApiStatus = new
		}
	}
}