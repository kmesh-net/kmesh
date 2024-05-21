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

#define map_of_manager      kmesh_manage
#define MAP_SIZE_OF_MANAGER 8192

/*
 * This map is used to store the cookie information
 * of pods managed by kmesh. The key represents the
 * cookie, and the value represents whether it is bypassed.
 * The default value is 0, indicating it is not
 * bypassed by default. A value of 1 represents bypassed
 * status. Whether it is managed by kmesh is unrelated
 * to the value. The only determining factor is whether
 * there is cookie information for this pod in the map.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, MAP_SIZE_OF_MANAGER);
    __uint(map_flags, 0);
} map_of_manager SEC(".maps");

static inline void record_netns_cookie(struct bpf_map *map, struct bpf_sock_addr *ctx)
{
    int err;
    int value = 0;
    __u64 cookie = bpf_get_netns_cookie(ctx);
    err = bpf_map_update_elem(map, &cookie, &value, BPF_NOEXIST);
    if (err)
        BPF_LOG(ERR, KMESH, "record netcookie failed!, err is %d\n", err);
}

void record_kmesh_netns_cookie(struct bpf_sock_addr *ctx)
{
    BPF_LOG(DEBUG, KMESH, "record_manager_netns_cookie");
    record_netns_cookie(&map_of_manager, ctx);
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

void record_bypass_netns_cookie(struct bpf_sock_addr *ctx)
{
    BPF_LOG(DEBUG, KMESH, "record_bypass_netns_cookie");
    set_netns_cookie_value(ctx, 1);
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

static inline void remove_netns_cookie(struct bpf_map *map, struct bpf_sock_addr *ctx)
{
    int err;
    __u64 cookie = bpf_get_netns_cookie(ctx);
    err = bpf_map_delete_elem(map, &cookie);
    if (err && err != -ENOENT)
        BPF_LOG(ERR, KMESH, "remove netcookie failed!, err is %d\n", err);
}

void remove_kmesh_netns_cookie(struct bpf_sock_addr *ctx)
{
    remove_netns_cookie(&map_of_manager, ctx);
}

void remove_bypass_netns_cookie(struct bpf_sock_addr *ctx)
{
    set_netns_cookie_value(ctx, 0);
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