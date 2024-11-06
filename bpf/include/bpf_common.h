/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_COMMON_H__
#define __KMESH_BPF_COMMON_H__

#include "common.h"
#include "inner_map_defs.h"

#define map_of_manager      kmesh_manage
#define MAP_SIZE_OF_MANAGER 8192
/*0x3a1(929) is the specific port handled by the cni to enable kmesh*/
#define ENABLE_KMESH_PORT 0x3a1
/*0x3a2(930) is the specific port handled by the cni to enable kmesh*/
#define DISABLE_KMESH_PORT 0x3a2

/* Ip(0.0.0.2 | ::2) used for control command, e.g. KmeshControl */
#define CONTROL_CMD_IP 2

#define MAP_SIZE_OF_OUTTER_MAP (1 << 20)

#define BPF_DATA_MAX_LEN                                                                                               \
    192 /* this value should be                                                                                        \
small that make compile success */

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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAP_SIZE_OF_OUTTER_MAP);
    __uint(map_flags, 0);
} outer_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, BPF_INNER_MAP_DATA_LEN);
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} inner_map SEC(".maps");

#if 1
// 64 128 1024 8192 81920

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
    __uint(map_flags, 0);
} outer_map_64 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
    __uint(map_flags, 0);
} outer_map_128 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
    __uint(map_flags, 0);
} outer_map_1024 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
    __uint(map_flags, 0);
} outer_map_8192 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, INNER_MAP_VS_64);
    __uint(max_entries, INNER_MAP_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} inner_map_64 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, INNER_MAP_VS_128);
    __uint(max_entries, INNER_MAP_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} inner_map_128 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, INNER_MAP_VS_1024);
    __uint(max_entries, INNER_MAP_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} inner_map_1024 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, INNER_MAP_VS_8192);
    __uint(max_entries, INNER_MAP_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} inner_map_8192 SEC(".maps");
#endif

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

static inline int kmesh_parse_mim_idx(__u32 mim_idx, void **outer_map, __u32 *outer_idx, __u32 *inner_idx)
{
    __u8 mim_type = MAP_IN_MAP_GET_TYPE(mim_idx);
    switch (mim_type) {
    case MAP_IN_MAP_TYPE_64:
        *outer_map = &outer_map_64;
        break;
    case MAP_IN_MAP_TYPE_128:
        *outer_map = &outer_map_128;
        break;
    case MAP_IN_MAP_TYPE_1024:
        *outer_map = &outer_map_1024;
        break;
    case MAP_IN_MAP_TYPE_8192:
        *outer_map = &outer_map_8192;
        break;
    default:
        return -1;
    }
    *inner_idx = MAP_IN_MAP_GET_INNER_IDX(mim_idx);
    *outer_idx = 0;
    return 0;
}

static inline void *kmesh_get_ptr_val(const void *ptr)
{
    /*
        map_in_map -- outer_map:
        key		value
        idx1	inner_map_fd1	// point to inner map1
        idx2	 inner_map_fd2	// point to inner map2

        structA.ptr_member1 = idx1;	// store idx in outer_map
    */
    void *inner_map_instance = NULL;
    __u32 mim_idx = (__u32)(uintptr_t)ptr;
    __u32 outer_idx, inner_idx;
    void *outer_map = NULL;

    int ret = kmesh_parse_mim_idx(mim_idx, &outer_map, &outer_idx, &inner_idx);
    if (ret)
        return NULL;

    /* get inner_map_instance by idx */
    inner_map_instance = kmesh_map_lookup_elem(outer_map, &outer_idx);
    if (!inner_map_instance) {
        return NULL;
    }

    /* get inner_map_instance value */
    void *val = kmesh_map_lookup_elem(inner_map_instance, &inner_idx);
    return INNER_MAP_GET_PTR_VAL(val);
}
#endif
