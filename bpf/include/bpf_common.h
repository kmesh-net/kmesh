/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_COMMON_H__
#define __KMESH_BPF_COMMON_H__

#include "common.h"

#define map_of_manager      kmesh_manage
#define MAP_SIZE_OF_MANAGER 8192
/*0x3a1(929) is the specific port handled by the cni to enable kmesh*/
#define ENABLE_KMESH_PORT 0x3a1
/*0x3a2(930) is the specific port handled by the cni to enable kmesh*/
#define DISABLE_KMESH_PORT 0x3a2

/* Ip(0.0.0.2 | ::2) used for control command, e.g. KmeshControl */
#define CONTROL_CMD_IP 2

struct manager_key {
    union {
        __u64 netns_cookie;
        struct ip_addr addr;
    };
};

/*
 * This map is used to store the cookie or ip information
 * of pods managed by kmesh.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct manager_key);
    __type(value, __u32);
    __uint(max_entries, MAP_SIZE_OF_MANAGER);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_of_manager SEC(".maps");

struct sock_storage_data {
    __u64 connect_ns;
    __u8 direction;
    __u8 connect_success;
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct sock_storage_data);
} map_of_sock_storage SEC(".maps");

/*
 * From v5.4, bpf_get_netns_cookie can be called for bpf cgroup hooks, from v5.15, it can be called for bpf sockops
 * hook. Therefore, ensure that function is correctly used.
 */
static inline void record_manager_netns_cookie(struct bpf_sock_addr *ctx)
{
    int err;
    struct manager_key key = {0};
    key.netns_cookie = bpf_get_netns_cookie(ctx);
    __u32 value = 0;

    err = bpf_map_update_elem(&map_of_manager, &key, &value, BPF_ANY);
    if (err)
        BPF_LOG(ERR, KMESH, "record netcookie failed!, err is %d\n", err);
}

/*
 * From v5.4, bpf_get_netns_cookie can be called for bpf cgroup hooks, from v5.15, it can be called for bpf sockops
 * hook. Therefore, ensure that function is correctly used.
 */
static inline bool is_kmesh_enabled(struct bpf_sock_addr *ctx)
{
    struct manager_key key = {0};
    key.netns_cookie = bpf_get_netns_cookie(ctx);
    return bpf_map_lookup_elem(&map_of_manager, &key);
}

/*
 * From v5.4, bpf_get_netns_cookie can be called for bpf cgroup hooks, from v5.15, it can be called for bpf sockops
 * hook. Therefore, ensure that function is correctly used.
 */
static inline void remove_manager_netns_cookie(struct bpf_sock_addr *ctx)
{
    int err;
    struct manager_key key = {0};
    key.netns_cookie = bpf_get_netns_cookie(ctx);

    err = bpf_map_delete_elem(&map_of_manager, &key);
    if (err && err != -ENOENT)
        BPF_LOG(ERR, KMESH, "remove netcookie failed!, err is %d\n", err);
}

static inline bool is_control_connect(struct kmesh_context *kmesh_ctx, __u32 ip, __u32 port)
{
    if (bpf_ntohs(kmesh_ctx->ctx->user_port) != port)
        return false;

    if (kmesh_ctx->ctx->family == AF_INET)
        return (bpf_ntohl(kmesh_ctx->orig_dst_addr.ip4) == ip);

    return (
        kmesh_ctx->orig_dst_addr.ip6[0] == 0 && kmesh_ctx->orig_dst_addr.ip6[1] == 0
        && kmesh_ctx->orig_dst_addr.ip6[2] == 0 && bpf_ntohl(kmesh_ctx->orig_dst_addr.ip6[3]) == ip);
}

static inline bool conn_from_cni_sim_add(struct kmesh_context *kmesh_ctx)
{
    // cni sim connect CONTROL_CMD_IP:929(0x3a1)
    // 0x3a1 is the specific port handled by the cni to enable Kmesh
    return is_control_connect(kmesh_ctx, CONTROL_CMD_IP, ENABLE_KMESH_PORT);
}

static inline bool conn_from_cni_sim_delete(struct kmesh_context *kmesh_ctx)
{
    // cni sim connect CONTROL_CMD_IP:930(0x3a2)
    // 0x3a2 is the specific port handled by the cni to disable Kmesh
    return is_control_connect(kmesh_ctx, CONTROL_CMD_IP, DISABLE_KMESH_PORT);
}

/* This function is used to store and delete cookie
 * records of pods managed by kmesh. When the record exists
 * and the value is 0, it means it is managed by kmesh.
 */
static inline bool handle_kmesh_manage_process(struct kmesh_context *kmesh_ctx)
{
    if (conn_from_cni_sim_add(kmesh_ctx)) {
        record_manager_netns_cookie(kmesh_ctx->ctx);
        // return failed, cni sim connect CONTROL_CMD_IP:929(0x3a1)
        // A normal program will not connect to this IP address
        return true;
    }

    if (conn_from_cni_sim_delete(kmesh_ctx)) {
        remove_manager_netns_cookie(kmesh_ctx->ctx);
        return true;
    }
    return false;
}

#endif