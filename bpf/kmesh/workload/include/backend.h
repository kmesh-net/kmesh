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
#ifndef __ROUTE_BACKEND_H__
#define __ROUTE_BACKEND_H__

#include "workload_common.h"
#include "encoder.h"
#include "tail_call.h"

#define TAIL_CALL_CONNECT4_INDEX 0

static inline backend_value *map_lookup_backend(const backend_key *key)
{
    return kmesh_map_lookup_elem(&map_of_backend, key);
}

static inline int waypoint_manager(ctx_buff_t *ctx, __u32 addr, __u32 port)
{
    int ret;
    address_t target_addr;
    __u64 *sk = (__u64 *)ctx->sk;
    struct bpf_sock_tuple value_tuple = {0};

    value_tuple.ipv4.daddr = ctx->user_ip4;
    value_tuple.ipv4.dport = ctx->user_port;

    ret = bpf_map_update_elem(&map_of_dst_info, &sk, &value_tuple, BPF_NOEXIST);
    if (ret) {
        BPF_LOG(ERR, BACKEND, "record metadata origin address and port failed, ret is %d\n", ret);
        return ret;
    }
    target_addr.ipv4 = addr;
    target_addr.port = port;
    SET_CTX_ADDRESS(ctx, target_addr);
    kmesh_workload_tail_call(ctx, TAIL_CALL_CONNECT4_INDEX);

    // if tail call failed will run this code
    BPF_LOG(ERR, BACKEND, "workload tail call failed, err is %d\n", ret);
    return -ENOEXEC;
}

static inline int backend_manager(ctx_buff_t *ctx, backend_value *backend_v, __u32 service_id, service_value *service_v)
{
    int ret;
    address_t target_addr;
    __u32 user_port = ctx->user_port;

    if (backend_v->waypoint_addr != 0 && backend_v->waypoint_port != 0) {
        BPF_LOG(
            DEBUG,
            BACKEND,
            "find waypoint addr=[%pI4h:%u]",
            &backend_v->waypoint_addr,
            bpf_ntohs(backend_v->waypoint_port));
        ret = waypoint_manager(ctx, backend_v->waypoint_addr, backend_v->waypoint_port);
        if (ret == -ENOEXEC) {
            BPF_LOG(ERR, BACKEND, "waypoint_manager failed, ret:%d\n", ret);
            return ret;
        }
    }

#pragma unroll
    for (__u32 i = 0; i < backend_v->service_count; i++) {
        if (i >= MAX_PORT_COUNT) {
            BPF_LOG(WARN, BACKEND, "exceed the max port count:%d", MAX_PORT_COUNT);
            return -EINVAL;
        }
        if (service_id == backend_v->service[i]) {
            BPF_LOG(DEBUG, BACKEND, "access the backend by service:%u\n", service_id);
#pragma unroll
            for (__u32 j = 0; j < MAX_PORT_COUNT; j++) {
                if (user_port == service_v->service_port[j]) {
                    target_addr.ipv4 = backend_v->ipv4;
                    target_addr.port = service_v->target_port[j];
                    SET_CTX_ADDRESS(ctx, target_addr);
                    BPF_LOG(
                        DEBUG,
                        BACKEND,
                        "get the backend addr=[%pI4h:%u]",
                        &target_addr.ipv4,
                        bpf_ntohs(target_addr.port));
                    return 0;
                }
            }
        }
    }

    BPF_LOG(ERR, BACKEND, "failed to get the backend\n");
    return -ENOENT;
}

#endif
