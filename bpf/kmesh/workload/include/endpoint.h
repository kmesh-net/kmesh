/*
 * Copyright 2024 The Kmesh Authors.
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

 * Author: kwb0523
 * Create: 2024-01-20
 */

#ifndef __KMESH_ENDPOINT_H__
#define __KMESH_ENDPOINT_H__

#include "workload_common.h"
#include "backend.h"

static inline endpoint_value *map_lookup_endpoint(const endpoint_key *key)
{
    return kmesh_map_lookup_elem(&map_of_endpoint, key);
}

static inline int endpoint_manager(ctx_buff_t *ctx, endpoint_value *endpoint_v)
{
    int ret = 0;
    backend_key backend_k = {0};
    backend_value *backend_v = NULL;

    backend_k.backend_uid = endpoint_v->backend_uid;
    backend_v = map_lookup_backend(&backend_k);
    if (!backend_v) {
        BPF_LOG(WARN, ENDPOINT, "find backend failed");
        return -ENOENT;
    }

    ret = backend_manager(ctx, backend_v);
    if (ret != 0) {
        if (ret != -ENOENT)
            BPF_LOG(ERR, ENDPOINT, "backend_manager failed, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

#endif
