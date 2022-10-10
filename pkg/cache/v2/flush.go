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

import core_v2 "openeuler.io/mesh/api/v2/core"

type CacheFactory interface {
	StatusFlush(status core_v2.ApiStatus) int
	StatusDelete(status core_v2.ApiStatus)
	StatusReset(old, new core_v2.ApiStatus)
}

func CacheFlush(cache CacheFactory) {
	cache.StatusReset(core_v2.ApiStatus_NONE, core_v2.ApiStatus_DELETE)
	cache.StatusFlush(core_v2.ApiStatus_UPDATE)
	cache.StatusFlush(core_v2.ApiStatus_DELETE)

	cache.StatusDelete(core_v2.ApiStatus_DELETE)
	cache.StatusReset(core_v2.ApiStatus_UPDATE, core_v2.ApiStatus_NONE)
}

func CacheDeltaFlush(cache CacheFactory) {
	cache.StatusFlush(core_v2.ApiStatus_UPDATE)
	cache.StatusFlush(core_v2.ApiStatus_DELETE)

	cache.StatusDelete(core_v2.ApiStatus_DELETE)
}
