/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#include "bpf_log.h"
#include "kmesh_common.h"
#include "bpf_common.h"

#ifndef __KMESH_CIRCUIT_BREAKER_H__
#define __KMESH_CIRCUIT_BREAKER_H__

#define CLUSTER_NAME_MAX_LEN BPF_DATA_MAX_LEN

struct cluster_stats {
    __u32 active_connections;
};

struct cluster_stats_key {
    __u64 netns_cookie;
    __u64 cluster_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct cluster_stats_key));
    __uint(value_size, sizeof(struct cluster_stats));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_CLUSTER);
} map_of_cluster_stats SEC(".maps");

struct cluster_sock_data {
    __u64 cluster_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct cluster_sock_data);
} map_of_cluster_sock SEC(".maps");

static inline void update_cluster_active_connections(const struct cluster_stats_key *key, int delta)
{
    if (!key) {
        return;
    }
    struct cluster_stats *stats = NULL;
    stats = kmesh_map_lookup_elem(&map_of_cluster_stats, key);
    if (!stats) {
        struct cluster_stats new_stats = {0};
        new_stats.active_connections = delta;
        BPF_LOG(
            DEBUG,
            KMESH,
            "create new stats(netns_cookie = %lld, cluster_id = %lld)",
            key->netns_cookie,
            key->cluster_id);
        kmesh_map_update_elem(&map_of_cluster_stats, key, &new_stats);
    } else {
        stats->active_connections += delta;
        kmesh_map_update_elem(&map_of_cluster_stats, key, stats);
        BPF_LOG(
            DEBUG,
            KMESH,
            "update existing stats(netns_cookie = %lld, cluster_id = %lld)",
            key->netns_cookie,
            key->cluster_id);
    }
}

static inline void on_cluster_sock_bind(struct bpf_sock *sk, const char *cluster_name)
{
    BPF_LOG(DEBUG, KMESH, "record sock bind for cluster %s\n", cluster_name);
    struct cluster_sock_data *data = NULL;
    if (!sk) {
        BPF_LOG(WARN, KMESH, "provided sock is NULL\n");
        return;
    }

    data = bpf_sk_storage_get(&map_of_cluster_sock, sk, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!data) {
        BPF_LOG(ERR, KMESH, "record_cluster_sock call bpf_sk_storage_get failed\n");
        return;
    }

    // bpf_strncpy(data->cluster_name, CLUSTER_NAME_MAX_LEN, (char *)cluster_name);
    // TODO(lzh): how to map cluster to id?
    data->cluster_id = 1;
    BPF_LOG(DEBUG, KMESH, "record sock bind for cluster %s done\n", cluster_name);
}

static inline struct cluster_sock_data *get_cluster_sk_data(struct bpf_sock *sk)
{
    struct cluster_sock_data *data = NULL;
    if (!sk) {
        BPF_LOG(DEBUG, KMESH, "provided sock is NULL\n");
        return NULL;
    }

    data = bpf_sk_storage_get(&map_of_cluster_sock, sk, 0, 0);
    return data;
}

static inline void on_cluster_sock_connect(struct bpf_sock_ops *ctx)
{
    if (!ctx) {
        return;
    }
    struct cluster_sock_data *data = get_cluster_sk_data(ctx->sk);
    if (!data) {
        return;
    }
    __u64 cookie = bpf_get_netns_cookie(ctx);
    BPF_LOG(INFO, KMESH, "here we got netns cookie: %lld", cookie);
    struct cluster_stats_key key = {0};
    key.netns_cookie = cookie;
    key.cluster_id = data->cluster_id;
    BPF_LOG(
        DEBUG,
        KMESH,
        "increase cluster active connections(netns_cookie = %lld, cluster = %lld)",
        key.netns_cookie,
        key.cluster_id);
    update_cluster_active_connections(&key, 1);
    BPF_LOG(DEBUG, KMESH, "record sock connection for cluster %lld\n", data->cluster_id);
}

static inline void on_cluster_sock_close(struct bpf_sock_ops *ctx)
{
    if (!ctx) {
        return;
    }
    struct cluster_sock_data *data = get_cluster_sk_data(ctx->sk);
    if (!data) {
        return;
    }
    __u64 cookie = bpf_get_netns_cookie(ctx);
    BPF_LOG(INFO, KMESH, "here we got netns cookie: %lld", cookie);
    struct cluster_stats_key key = {0};
    key.netns_cookie = cookie;
    key.cluster_id = data->cluster_id;
    update_cluster_active_connections(&key, -1);
    BPF_LOG(
        DEBUG,
        KMESH,
        "decrease cluster active connections(netns_cookie = %lld, cluster = %lld)",
        key.netns_cookie,
        key.cluster_id);
    BPF_LOG(DEBUG, KMESH, "record sock close for cluster %lld", data->cluster_id);
}

#endif