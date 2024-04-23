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
#ifndef __KMESH_FRONTEND_H__
#define __KMESH_FRONTEND_H__

#include "workload_common.h"
#include "service.h"

static inline frontend_value *map_lookup_frontend(const frontend_key *key)
{
    return kmesh_map_lookup_elem(&map_of_frontend, key);
}

static inline int frontend_manager(ctx_buff_t *ctx, frontend_value *frontend_v)
{
    int ret = 0;
    service_key service_k = {0};
    service_value *service_v = NULL;

    service_k.service_id = frontend_v->upstream_id;
    service_v = map_lookup_service(&service_k);
    if (!service_v) {
        BPF_LOG(WARN, FRONTEND, "find service failed\n");
        return -ENOENT;
    }

    ret = service_manager(ctx, frontend_v->upstream_id, service_v);
    if (ret != 0) {
        if (ret != -ENOENT)
            BPF_LOG(ERR, FRONTEND, "service_manager failed, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

#endif
