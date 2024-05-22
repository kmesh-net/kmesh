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
 */

#ifndef __KMESH_BPF_COMMON_H__
#define __KMESH_BPF_COMMON_H__

#include "common.h"

#define map_of_manager      kmesh_manage
#define MAP_SIZE_OF_MANAGER 8192

struct manager_key {
    union {
        __u64 netns_cookie;
        struct ip_addr addr;
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct manager_key);
    __type(value, __u32);
    __uint(max_entries, MAP_SIZE_OF_MANAGER);
    __uint(map_flags, 0);
} map_of_manager SEC(".maps");

static inline void record_netns_cookie(struct bpf_sock_addr *ctx)
{
    int err;
    int value = 0;
    struct manager_key key = {0};
    key.netns_cookie = bpf_get_netns_cookie(ctx);

    err = bpf_map_update_elem(&map_of_manager, &key, &value, BPF_NOEXIST);
    if (err)
        BPF_LOG(ERR, KMESH, "record netcookie failed!, err is %d\n", err);
}

static inline void remove_netns_cookie(struct bpf_sock_addr *ctx)
{
    int err;
    struct manager_key key = {0};
    key.netns_cookie = bpf_get_netns_cookie(ctx);

    err = bpf_map_delete_elem(&map_of_manager, &key);
    if (err && err != -ENOENT)
        BPF_LOG(ERR, KMESH, "remove netcookie failed!, err is %d\n", err);
}

static inline bool check_kmesh_enabled(struct bpf_sock_addr *ctx)
{
    struct manager_key key = {0};
    key.netns_cookie = bpf_get_netns_cookie(ctx);
    return bpf_map_lookup_elem(&map_of_manager, &key);
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

#endif
