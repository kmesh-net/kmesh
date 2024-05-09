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

#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/tcp.h>
#include "bpf_log.h"
#include "ctx/sock_addr.h"
#include "frontend.h"

static inline void record_netns_cookie(struct bpf_sock_addr *ctx)
{
    int err;
    int value = 0;
    __u64 cookie = bpf_get_netns_cookie(ctx);
    err = bpf_map_update_elem(&map_of_manager, &cookie, &value, BPF_NOEXIST);
    if (err)
        BPF_LOG(ERR, KMESH, "record netcookie failed!, err is %d\n", err);
}

static inline void remove_netns_cookie(struct bpf_sock_addr *ctx)
{
    __u64 cookie = bpf_get_netns_cookie(ctx);
    int err = bpf_map_delete_elem(&map_of_manager, &cookie);
    if (err && err != -ENOENT)
        BPF_LOG(ERR, KMESH, "remove netcookie failed!, err is %d\n", err);
}

static inline bool check_kmesh_enabled(struct bpf_sock_addr *ctx)
{
    __u64 cookie = bpf_get_netns_cookie(ctx);
    return bpf_map_lookup_elem(&map_of_manager, &cookie);
}

static inline int sock4_traffic_control(struct bpf_sock_addr *ctx)
{
    int ret;
    frontend_value *frontend_v = NULL;

    if (!check_kmesh_enabled(ctx))
        return 0;

    DECLARE_FRONTEND_KEY(ctx, frontend_k);

    BPF_LOG(DEBUG, KMESH, "origin addr=[%u:%u]\n", ctx->user_ip4, ctx->user_port);
    frontend_v = map_lookup_frontend(&frontend_k);
    if (!frontend_v) {
        return -ENOENT;
    }

    BPF_LOG(DEBUG, KMESH, "bpf find frontend addr=[%u:%u]\n", ctx->user_ip4, ctx->user_port);
    ret = frontend_manager(ctx, frontend_v);
    if (ret != 0) {
        if (ret != -ENOENT)
            BPF_LOG(ERR, KMESH, "frontend_manager failed, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

static inline bool conn_from_cni_sim_add(struct bpf_sock_addr *ctx)
{
    // cni sim connect 0.0.0.0:929(0x3a1)
    // 0x3a1 is the specific port handled by the cni for enable Kmesh
    return ((bpf_ntohl(ctx->user_ip4) == 1) && (bpf_ntohl(ctx->user_port) == 0x3a10000));
}

static inline bool conn_from_cni_sim_delete(struct bpf_sock_addr *ctx)
{
    // cni sim connect 0.0.0.1:930(0x3a2)
    // 0x3a2 is the specific port handled by the cni for disable Kmesh
    return ((bpf_ntohl(ctx->user_ip4) == 1) && (bpf_ntohl(ctx->user_port) == 0x3a20000));
}

SEC("cgroup/connect4")
int cgroup_connect4_prog(struct bpf_sock_addr *ctx)
{
    if (conn_from_cni_sim_add(ctx)) {
        record_netns_cookie(ctx);
        // return failed, cni sim connect 0.0.0.1:929(0x3a1)
        // A normal program will not connect to this IP address
        return CGROUP_SOCK_OK;
    }
    if (conn_from_cni_sim_delete(ctx)) {
        remove_netns_cookie(ctx);
        return CGROUP_SOCK_OK;
    }
    int ret = sock4_traffic_control(ctx);
    return CGROUP_SOCK_OK;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
