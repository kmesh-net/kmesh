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
    __u32 cluster_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct cluster_stats_key));
    __uint(value_size, sizeof(struct cluster_stats));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_CLUSTER);
} map_of_cluster_stats SEC(".maps");

struct cluster_sock_data {
    __u32 cluster_id;
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
        struct cluster_stats init_value = {0};
        bpf_map_update_elem(&map_of_cluster_stats, key, &init_value, BPF_NOEXIST);
        stats = kmesh_map_lookup_elem(&map_of_cluster_stats, key);
    }

    if (!stats) {
        BPF_LOG(ERR, CIRCUIT_BREAKER, "failed to get cluster stats");
        return;
    }
    if (delta < 0 && -delta > stats->active_connections) {
        BPF_LOG(ERR, CIRCUIT_BREAKER, "invalid delta update");
        return;
    }

    __sync_fetch_and_add(&stats->active_connections, delta);

    BPF_LOG(
        DEBUG,
        CIRCUIT_BREAKER,
        "update existing stats(netns_cookie = %lld, cluster_id = %ld), current active connections: %d",
        key->netns_cookie,
        key->cluster_id,
        stats->active_connections);
}

static inline int on_cluster_sock_bind(ctx_buff_t *ctx, const Cluster__Cluster *cluster)
{
    __u32 cluster_id = cluster->id;
    struct cluster_stats_key key = {0};
    __u64 cookie = bpf_get_netns_cookie(ctx);
    key.cluster_id = cluster_id;
    key.netns_cookie = cookie;
    struct cluster_stats *stats = NULL;
    stats = kmesh_map_lookup_elem(&map_of_cluster_stats, &key);

    if (stats != NULL) {
        Cluster__CircuitBreakers *cbs = NULL;
        cbs = kmesh_get_ptr_val(cluster->circuit_breakers);
        if (cbs != NULL && stats->active_connections >= cbs->max_connections) {
            BPF_LOG(
                DEBUG,
                CIRCUIT_BREAKER,
                "Current active connections %d exceeded max connections %d, reject connection",
                stats->active_connections,
                cbs->max_connections);
            return -1;
        }
    }

    BPF_LOG(DEBUG, CIRCUIT_BREAKER, "record sock bind for cluster id = %ld", cluster_id);

    struct cluster_sock_data *data = NULL;
    if (!ctx->sk) {
        BPF_LOG(WARN, CIRCUIT_BREAKER, "provided sock is NULL");
        return 0;
    }
    data = bpf_sk_storage_get(&map_of_cluster_sock, ctx->sk, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!data) {
        BPF_LOG(ERR, CIRCUIT_BREAKER, "on_cluster_sock_bind call bpf_sk_storage_get failed");
        return 0;
    }
    data->cluster_id = cluster_id;
    return 0;
}

static inline struct cluster_sock_data *get_cluster_sk_data(struct bpf_sock *sk)
{
    struct cluster_sock_data *data = NULL;
    if (!sk) {
        BPF_LOG(DEBUG, CIRCUIT_BREAKER, "provided sock is NULL");
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
    struct cluster_stats_key key = {0};
    key.netns_cookie = cookie;
    key.cluster_id = data->cluster_id;
    BPF_LOG(
        DEBUG,
        CIRCUIT_BREAKER,
        "increase cluster active connections(netns_cookie = %lld, cluster id = %ld)",
        key.netns_cookie,
        key.cluster_id);
    update_cluster_active_connections(&key, 1);
    BPF_LOG(DEBUG, CIRCUIT_BREAKER, "record sock connection for cluster id = %ld", data->cluster_id);
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
    struct cluster_stats_key key = {0};
    key.netns_cookie = cookie;
    key.cluster_id = data->cluster_id;
    update_cluster_active_connections(&key, -1);
    BPF_LOG(
        DEBUG,
        CIRCUIT_BREAKER,
        "decrease cluster active connections(netns_cookie = %lld, cluster id = %ld)",
        key.netns_cookie,
        key.cluster_id);
    BPF_LOG(DEBUG, CIRCUIT_BREAKER, "record sock close for cluster id = %ld", data->cluster_id);
}

#endif