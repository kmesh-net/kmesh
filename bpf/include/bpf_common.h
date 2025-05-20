/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_COMMON_H__
#define __KMESH_BPF_COMMON_H__

#include "common.h"
#include "inner_map_defs.h"
#include "map_config.h"

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
    __u64 last_report_ns;
    __u8 direction;
    __u8 connect_success;
    // whether has to proxied by waypoint
    bool via_waypoint;
    // whether tlv encoded
    bool has_encoded;
    // prevent duplicating setting of original dst
    bool has_set_ip;
    // original dst info
    struct bpf_sock_tuple sk_tuple;
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct sock_storage_data);
} map_of_sock_storage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAP_VAL_SIZE_64);
    __uint(max_entries, MAP_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} kmesh_map64 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAP_VAL_SIZE_192);
    __uint(max_entries, MAP_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} kmesh_map192 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAP_VAL_SIZE_296);
    __uint(max_entries, MAP_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} kmesh_map296 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAP_VAL_SIZE_1600);
    __uint(max_entries, MAP_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} kmesh_map1600 SEC(".maps");

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

static inline void kmesh_parse_outer_key(__u32 outer_key, __u8 *type, __u32 *inner_idx)
{
    *type = MAP_GET_TYPE(outer_key);
    *inner_idx = MAP_GET_INDEX(outer_key);
    return;
}

static inline void *get_ptr_val_from_map(void *map, __u8 map_type, const void *ptr)
{
    __u8 type;
    __u32 inner_idx;
    __u32 outer_key = (__u32)(uintptr_t)ptr;

    kmesh_parse_outer_key(outer_key, &type, &inner_idx);
    if (type != map_type)
        return NULL;

    return kmesh_map_lookup_elem(map, &inner_idx);
}

#define KMESH_GET_PTR_VAL(ptr, type)                                                                                   \
    ({                                                                                                                 \
        void *val_tmp = NULL;                                                                                          \
        if (sizeof(type) == sizeof(void *)) {                                                                          \
            if (__builtin_types_compatible_p(type, char *))                                                            \
                val_tmp = get_ptr_val_from_map(&kmesh_map192, MAP_TYPE_192, ptr);                                      \
            else if (__builtin_types_compatible_p(type, void *))                                                       \
                val_tmp = get_ptr_val_from_map(&kmesh_map1600, MAP_TYPE_1600, ptr);                                    \
            else if (__builtin_types_compatible_p(type, void **))                                                      \
                val_tmp = get_ptr_val_from_map(&kmesh_map1600, MAP_TYPE_1600, ptr);                                    \
            else if (__builtin_types_compatible_p(type, struct byte *))                                                \
                val_tmp = get_ptr_val_from_map(&kmesh_map64, MAP_TYPE_64, ptr);                                        \
            else                                                                                                       \
                val_tmp = get_ptr_val_from_map(&kmesh_map64, MAP_TYPE_64, ptr);                                        \
        } else if (sizeof(type) <= MAP_VAL_SIZE_64)                                                                    \
            val_tmp = get_ptr_val_from_map(&kmesh_map64, MAP_TYPE_64, ptr);                                            \
        else if (sizeof(type) <= MAP_VAL_SIZE_192)                                                                     \
            val_tmp = get_ptr_val_from_map(&kmesh_map192, MAP_TYPE_192, ptr);                                          \
        else if (sizeof(type) <= MAP_VAL_SIZE_296)                                                                     \
            val_tmp = get_ptr_val_from_map(&kmesh_map296, MAP_TYPE_296, ptr);                                          \
        else if (sizeof(type) <= MAP_VAL_SIZE_1600)                                                                    \
            val_tmp = get_ptr_val_from_map(&kmesh_map1600, MAP_TYPE_1600, ptr);                                        \
        else                                                                                                           \
            val_tmp = NULL;                                                                                            \
        val_tmp;                                                                                                       \
    })

static inline void record_kmesh_managed_ip(__u32 family, __u32 ip4, __u32 *ip6)
{
    int err;
    __u32 value = 0;
    struct manager_key key = {0};
    if (family == AF_INET)
        key.addr.ip4 = ip4;
    if (family == AF_INET6 && ip6)
        IP6_COPY(key.addr.ip6, ip6);

    err = bpf_map_update_elem(&map_of_manager, &key, &value, BPF_ANY);
    if (err)
        BPF_LOG(ERR, KMESH, "record ip failed, err is %d\n", err);
}

static inline void remove_kmesh_managed_ip(__u32 family, __u32 ip4, __u32 *ip6)
{
    struct manager_key key = {0};
    if (family == AF_INET)
        key.addr.ip4 = ip4;
    if (family == AF_INET6 && ip6)
        IP6_COPY(key.addr.ip6, ip6);

    int err = bpf_map_delete_elem(&map_of_manager, &key);
    if (err && err != -ENOENT)
        BPF_LOG(ERR, KMESH, "remove ip failed, err is %d\n", err);
}

static inline bool sock_conn_from_sim(struct __sk_buff *skb)
{
    __u16 dst_port = (__u16)(skb->remote_port >> 16);
    if (bpf_ntohs(dst_port) != ENABLE_KMESH_PORT && bpf_ntohs(dst_port) != DISABLE_KMESH_PORT)
        return false;

    if (skb->protocol == AF_INET)
        return bpf_ntohl(skb->remote_ip4) == CONTROL_CMD_IP;
    // If directly read skb->remote_ip6. bpf prog load would fail with permission denied.
    __u32 remote_ip6[4] = {0};
    bpf_skb_load_bytes(skb, offsetof(struct __sk_buff, remote_ip6), &remote_ip6, sizeof(remote_ip6));
    return (
        remote_ip6[0] == 0 && remote_ip6[1] == 0 && remote_ip6[2] == 0 && bpf_ntohl(remote_ip6[3]) == CONTROL_CMD_IP);
}

static inline bool conn_from_sim(struct bpf_sock_ops *skops, __u32 ip, __u16 port)
{
    __u16 remote_port = GET_SKOPS_REMOTE_PORT(skops);
    if (bpf_ntohs(remote_port) != port)
        return false;

    if (skops->family == AF_INET)
        return (bpf_ntohl(skops->remote_ip4) == ip);

    return (
        skops->remote_ip6[0] == 0 && skops->remote_ip6[1] == 0 && skops->remote_ip6[2] == 0
        && bpf_ntohl(skops->remote_ip6[3]) == ip);
}

static inline bool skops_conn_from_cni_sim_add(struct bpf_sock_ops *skops)
{
    // cni sim connect CONTROL_CMD_IP:929(0x3a1)
    // 0x3a1 is the specific port handled by the cni to enable Kmesh
    return conn_from_sim(skops, CONTROL_CMD_IP, ENABLE_KMESH_PORT);
}

static inline bool skops_conn_from_cni_sim_delete(struct bpf_sock_ops *skops)
{
    // cni sim connect CONTROL_CMD_IP:930(0x3a2)
    // 0x3a2 is the specific port handled by the cni to disable Kmesh
    return conn_from_sim(skops, CONTROL_CMD_IP, DISABLE_KMESH_PORT);
}

static inline void skops_handle_kmesh_managed_process(struct bpf_sock_ops *skops)
{
    if (skops_conn_from_cni_sim_add(skops))
        record_kmesh_managed_ip(skops->family, skops->local_ip4, skops->local_ip6);
    if (skops_conn_from_cni_sim_delete(skops))
        remove_kmesh_managed_ip(skops->family, skops->local_ip4, skops->local_ip6);
}

static inline bool is_managed_by_kmesh(struct bpf_sock_ops *skops)
{
    struct manager_key key = {0};
    if (skops->family == AF_INET)
        key.addr.ip4 = skops->local_ip4;
    if (skops->family == AF_INET6) {
        if (is_ipv4_mapped_addr(skops->local_ip6))
            key.addr.ip4 = skops->local_ip6[3];
        else
            IP6_COPY(key.addr.ip6, skops->local_ip6);
    }

    int *value = bpf_map_lookup_elem(&map_of_manager, &key);
    if (!value)
        return false;
    return (*value == 0);
}

static inline bool is_managed_by_kmesh_skb(struct __sk_buff *skb)
{
    struct manager_key key = {0};
    if (skb->family == AF_INET)
        key.addr.ip4 = skb->local_ip4;
    if (skb->family == AF_INET6) {
        if (is_ipv4_mapped_addr(skb->local_ip6))
            key.addr.ip4 = skb->local_ip6[3];
        else
            IP6_COPY(key.addr.ip6, skb->local_ip6);
    }

    int *value = bpf_map_lookup_elem(&map_of_manager, &key);
    if (!value)
        return false;
    return (*value == 0);
}
#endif