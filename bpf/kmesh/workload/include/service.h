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
#ifndef __KMESH_SERVICE_H__
#define __KMESH_SERVICE_H__

#include "workload_common.h"
#include "endpoint.h"

static inline service_value *map_lookup_service(const service_key *key)
{
    return kmesh_map_lookup_elem(&map_of_service, key);
}

static inline int lb_random_handle(ctx_buff_t *ctx, int service_id, service_value *service_v)
{
    int ret = 0;
    endpoint_key endpoint_k = {0};
    endpoint_value *endpoint_v = NULL;

    endpoint_k.service_id = service_id;
    endpoint_k.backend_index = bpf_get_prandom_u32() % service_v->endpoint_count + 1;

    endpoint_v = map_lookup_endpoint(&endpoint_k);
    if (!endpoint_v) {
        BPF_LOG(WARN, SERVICE, "find endpoint failed");
        return -ENOENT;
    }

    ret = endpoint_manager(ctx, endpoint_v);
    if (ret != 0) {
        if (ret != -ENOENT)
            BPF_LOG(ERR, SERVICE, "endpoint_manager failed, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

static inline int service_manager(ctx_buff_t *ctx, int service_id, service_value *service_v)
{
    int ret = 0;

    BPF_LOG(DEBUG, SERVICE, "load balance type:%u", service_v->lb_policy);
    switch (service_v->lb_policy) {
    case LB_POLICY_RANDOM:
        ret = lb_random_handle(ctx, service_id, service_v);
        break;
    defalut:
        BPF_LOG(ERR, SERVICE, "unsupport load balance type:%u\n", service_v->lb_policy);
        ret = -EINVAL;
        break;
    }

    return ret;
}

#endif
