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

static inline void record_netns_cookie(struct bpf_map *map, struct bpf_sock_addr *ctx)
{
    int err;
    int value = 0;
    __u64 cookie = bpf_get_netns_cookie(ctx);
    err = bpf_map_update_elem(map, &cookie, &value, BPF_NOEXIST);
    if (err)
        BPF_LOG(ERR, KMESH, "record netcookie failed!, err is %d\n", err);
}

static inline void remove_netns_cookie(struct bpf_map *map, struct bpf_sock_addr *ctx)
{
    int err;
    __u64 cookie = bpf_get_netns_cookie(ctx);
    err = bpf_map_delete_elem(map, &cookie);
    if (err && err != -ENOENT)
        BPF_LOG(ERR, KMESH, "remove netcookie failed!, err is %d\n", err);
}

void set_netns_cookie_value(struct bpf_sock_addr *ctx, int value)
{
    __u64 cookie = bpf_get_netns_cookie(ctx);
    int *old_value = bpf_map_lookup_elem(&map_of_manager, &cookie);
    if (!old_value || *old_value == value)
        return;

    int err = bpf_map_update_elem(&map_of_manager, &cookie, &value, BPF_EXIST);
    if (err)
        BPF_LOG(ERR, KMESH, "set netcookie failed!, err is %d\n", err);
}

void record_kmesh_netns_cookie(struct bpf_sock_addr *ctx)
{
    BPF_LOG(DEBUG, KMESH, "record_manager_netns_cookie");
    record_netns_cookie(&map_of_manager, ctx);
}

void record_bypass_netns_cookie(struct bpf_sock_addr *ctx)
{
    BPF_LOG(DEBUG, KMESH, "record_bypass_netns_cookie");
    set_netns_cookie_value(ctx, 1);
}

void remove_kmesh_netns_cookie(struct bpf_sock_addr *ctx)
{
    remove_netns_cookie(&map_of_manager, ctx);
}

void remove_bypass_netns_cookie(struct bpf_sock_addr *ctx)
{
    set_netns_cookie_value(ctx, 0);
}

static inline bool check_kmesh_enabled(struct bpf_sock_addr *ctx)
{
    __u64 cookie = bpf_get_netns_cookie(ctx);
    return bpf_map_lookup_elem(&map_of_manager, &cookie);
}

static inline bool check_bypass_enabled(struct bpf_sock_addr *ctx)
{
    __u64 cookie = bpf_get_netns_cookie(ctx);
    int *value = bpf_map_lookup_elem(&map_of_manager, &cookie);

    if (!value)
        return false;

    return (*value == 1);
}

static inline bool conn_from_bypass_sim_add(struct bpf_sock_addr *ctx)
{
    // daemon sim connect 0.0.0.0:931(0x3a3)
    // 0x3a3 is the specific port handled by the daemon for enable bypass
    return ((bpf_ntohl(ctx->user_ip4) == 1) && (bpf_ntohl(ctx->user_port) == 0x3a30000));
}

static inline bool conn_from_bypass_sim_delete(struct bpf_sock_addr *ctx)
{
    // daemon sim connect 0.0.0.1:932(0x3a4)
    // 0x3a4 is the specific port handled by the daemon for disable bypass
    return ((bpf_ntohl(ctx->user_ip4) == 1) && (bpf_ntohl(ctx->user_port) == 0x3a40000));
}

static inline int sock4_traffic_control(struct bpf_sock_addr *ctx)
{
    int ret;
    frontend_value *frontend_v = NULL;

    if (ctx->protocol != IPPROTO_TCP)
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

static inline bool check_mgn_process(struct bpf_sock_addr *ctx)
{
    if (conn_from_cni_sim_add(ctx)) {
        record_kmesh_netns_cookie(ctx);
        // return failed, cni sim connect 0.0.0.1:929(0x3a1)
        // A normal program will not connect to this IP address
        return true;
    }

    if (conn_from_cni_sim_delete(ctx)) {
        remove_kmesh_netns_cookie(ctx);
        return true;
    }
    return false;
}

static inline bool check_bypass_process(struct bpf_sock_addr *ctx)
{
    if (conn_from_bypass_sim_add(ctx)) {
        record_bypass_netns_cookie(ctx);
        // return failed, cni sim connect 0.0.0.1:929(0x3a1)
        // A normal program will not connect to this IP address
        return true;
    }
    if (conn_from_bypass_sim_delete(ctx)) {
        remove_bypass_netns_cookie(ctx);
        return true;
    }
    return false;
}
SEC("cgroup/connect4")
int cgroup_connect4_prog(struct bpf_sock_addr *ctx)
{
    if (check_mgn_process(ctx) || !check_kmesh_enabled(ctx)) {
        return CGROUP_SOCK_OK;
    }

    if (check_bypass_process(ctx) || check_bypass_enabled(ctx)) {
        return CGROUP_SOCK_OK;
    }
    int ret = sock4_traffic_control(ctx);
    return CGROUP_SOCK_OK;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;