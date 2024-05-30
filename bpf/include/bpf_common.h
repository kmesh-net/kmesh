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
/*0x3a1(929) is the specific port handled by the cni to enable kmesh*/
#define ENABLE_KMESH_PORT 0x3a1
/*0x3a2(930) is the specific port handled by the cni to enable kmesh*/
#define DISABLE_KMESH_PORT 0x3a2
/*0x3a3(931) is the specific port handled by the daemon to enable bypass*/
#define ENABLE_BYPASS_PORT 0x3a3
/*0x3a4(932) is the specific port handled by the daemon to enable bypass*/
#define DISABLE_BYPASS_PORT 0x3a4

typedef struct {
    __u32 is_bypassed;
} manager_value_t;
/*
 * This map is used to store the cookie information
 * of pods managed by kmesh. The key represents the
 * cookie, and the value of is_bypassed represents
 * whether it is bypassed.
 * The default value is 0, indicating it is not
 * bypassed by default. A value of 1 represents bypassed
 * status. Whether it is managed by kmesh is unrelated
 * to the value. The only determining factor is whether
 * there is cookie information for this pod in the map.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, manager_value_t);
    __uint(max_entries, MAP_SIZE_OF_MANAGER);
    __uint(map_flags, 0);
} map_of_manager SEC(".maps");

static inline void record_manager_netns_cookie(struct bpf_map *map, struct bpf_sock_addr *ctx)
{
    int err;
    manager_value_t value = {
        .is_bypassed = 0,
    };

    __u64 cookie = bpf_get_netns_cookie(ctx);
    err = bpf_map_update_elem(map, &cookie, &value, BPF_NOEXIST);
    if (err)
        BPF_LOG(ERR, KMESH, "record netcookie failed!, err is %d\n", err);
}

static inline void set_netns_bypass_value(struct bpf_sock_addr *sock_addr, int new_bypass_value)
{
    __u64 cookie = bpf_get_netns_cookie(sock_addr);
    manager_value_t *current_value = bpf_map_lookup_elem(&map_of_manager, &cookie);
    if (!current_value || current_value->is_bypassed == new_bypass_value)
        return;

    current_value->is_bypassed = new_bypass_value;

    int err = bpf_map_update_elem(&map_of_manager, &cookie, current_value, BPF_EXIST);
    if (err)
        BPF_LOG(ERR, KMESH, "set netcookie failed!, err is %d\n", err);
}

static inline bool is_kmesh_enabled(struct bpf_sock_addr *ctx)
{
    __u64 cookie = bpf_get_netns_cookie(ctx);
    return bpf_map_lookup_elem(&map_of_manager, &cookie);
}

static inline bool is_bypass_enabled(struct bpf_sock_addr *ctx)
{
    __u64 cookie = bpf_get_netns_cookie(ctx);
    manager_value_t *value = bpf_map_lookup_elem(&map_of_manager, &cookie);

    if (!value)
        return false;

    return value->is_bypassed;
}

static inline void remove_manager_netns_cookie(struct bpf_map *map, struct bpf_sock_addr *ctx)
{
    int err;
    __u64 cookie = bpf_get_netns_cookie(ctx);
    err = bpf_map_delete_elem(map, &cookie);
    if (err && err != -ENOENT)
        BPF_LOG(ERR, KMESH, "remove netcookie failed!, err is %d\n", err);
}

static inline bool conn_from_bypass_sim_add(struct bpf_sock_addr *ctx)
{
    // daemon sim connect 0.0.0.0:931(0x3a3)
    // 0x3a3 is the specific port handled by the daemon to enable bypass
    return ((bpf_ntohl(ctx->user_ip4) == 1) && (bpf_ntohs(ctx->user_port) == ENABLE_BYPASS_PORT));
}

static inline bool conn_from_bypass_sim_delete(struct bpf_sock_addr *ctx)
{
    // daemon sim connect 0.0.0.1:932(0x3a4)
    // 0x3a4 is the specific port handled by the daemon to disable bypass
    return ((bpf_ntohl(ctx->user_ip4) == 1) && (bpf_ntohs(ctx->user_port) == DISABLE_BYPASS_PORT));
}

static inline bool conn_from_cni_sim_add(struct bpf_sock_addr *ctx)
{
    // cni sim connect 0.0.0.0:929(0x3a1)
    // 0x3a1 is the specific port handled by the cni to enable Kmesh
    return ((bpf_ntohl(ctx->user_ip4) == 1) && (bpf_ntohs(ctx->user_port) == ENABLE_KMESH_PORT));
}

static inline bool conn_from_cni_sim_delete(struct bpf_sock_addr *ctx)
{
    // cni sim connect 0.0.0.1:930(0x3a2)
    // 0x3a2 is the specific port handled by the cni to disable Kmesh
    return ((bpf_ntohl(ctx->user_ip4) == 1) && (bpf_ntohs(ctx->user_port) == DISABLE_KMESH_PORT));
}

/* This function is used to store and delete cookie
 * records of pods managed by kmesh. When the record exists
 * and the value is 0, it means it is managed by kmesh.
 */
static inline bool handle_kmesh_manage_process(struct bpf_sock_addr *ctx)
{
    if (conn_from_cni_sim_add(ctx)) {
        record_manager_netns_cookie(&map_of_manager, ctx);
        // return failed, cni sim connect 0.0.0.1:929(0x3a1)
        // A normal program will not connect to this IP address
        return true;
    }

    if (conn_from_cni_sim_delete(ctx)) {
        remove_manager_netns_cookie(&map_of_manager, ctx);
        return true;
    }
    return false;
}

/* This function is used to modify the value of the
 * record in the manager map. When the value is 0, it
 * means that it has not been bypassed. When it is 1,
 * it means that it has been bypassed.
 */
static inline bool handle_bypass_process(struct bpf_sock_addr *ctx)
{
    if (conn_from_bypass_sim_add(ctx)) {
        set_netns_bypass_value(ctx, 1);
        return true;
    }
    if (conn_from_bypass_sim_delete(ctx)) {
        set_netns_bypass_value(ctx, 0);
        return true;
    }
    return false;
}