/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
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

import core_v2 "openmesh.io/mesh/api/v2/core"

type CacheFactory interface {
	StatusFlush(status core_v2.ApiStatus) int
	StatusDelete(status core_v2.ApiStatus)
	StatusReset(old, new core_v2.ApiStatus)
}

// CacheFlush ApiStatus_NONE: indicates that the resource is not included in this response
// need delete it, so reset to ApiStatus_DELETE
// ApiStatus_UPDATE: indicates that the resource need update
// ApiStatus_UNCHANGED:indicates that the resource is not changed in this response
func CacheFlush(cache CacheFactory) {
	cache.StatusReset(core_v2.ApiStatus_NONE, core_v2.ApiStatus_DELETE)
	cache.StatusFlush(core_v2.ApiStatus_UPDATE)
	cache.StatusFlush(core_v2.ApiStatus_DELETE)

	cache.StatusDelete(core_v2.ApiStatus_DELETE)
	cache.StatusReset(core_v2.ApiStatus_UPDATE, core_v2.ApiStatus_NONE)
	cache.StatusReset(core_v2.ApiStatus_UNCHANGED, core_v2.ApiStatus_NONE)
}

func CacheDeltaFlush(cache CacheFactory) {
	cache.StatusFlush(core_v2.ApiStatus_UPDATE)
	cache.StatusFlush(core_v2.ApiStatus_DELETE)

	cache.StatusDelete(core_v2.ApiStatus_DELETE)
}
