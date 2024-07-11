// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_METRICS_H__
#define __KMESH_BPF_METRICS_H__
#include "bpf_common.h"

// metrics
struct metric_key {
    struct ip_addr src_ip;
    struct ip_addr dst_ip;
};

struct metric_data {
    __u32 direction;      // update on connect
    __u32 conn_open;      // update on connect
    __u32 conn_close;     // update on close
    __u32 conn_failed;    // update on close
    __u32 sent_bytes;     // update on close
    __u32 received_bytes; // update on close
};

#define MAP_SIZE_OF_METRICS 100000
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct metric_key);
    __type(value, struct metric_data);
    __uint(max_entries, MAP_SIZE_OF_METRICS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_of_metrics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} map_of_metric_notify SEC(".maps");

static inline void construct_metric_key(struct bpf_sock *sk, struct metric_key *key)
{
    if (sk->family == AF_INET) {
        key->src_ip.ip4 = sk->src_ip4;
        key->dst_ip.ip4 = sk->dst_ip4;
    } else {
        bpf_memcpy(key->src_ip.ip6, sk->src_ip6, IPV6_ADDR_LEN);
        bpf_memcpy(key->dst_ip.ip6, sk->dst_ip6, IPV6_ADDR_LEN);
    }
    return;
}

static inline void report_metrics(struct bpf_sock *sk)
{
    struct metric_key *key = bpf_ringbuf_reserve(&map_of_metric_notify, sizeof(struct metric_key), 0);
    if (!key) {
        BPF_LOG(ERR, PROBE, "report_metrics bpf_ringbuf_reserve failed\n");
        return;
    }

    construct_metric_key(sk, key);
    bpf_ringbuf_submit(key, 0);
    return;
}

static inline void
metric_on_connect(struct bpf_sock *sk, struct bpf_tcp_sock *tcp_sock, struct sock_storage_data *storage)
{
    struct metric_key key = {0};
    struct metric_data data = {0};
    struct metric_data *metric = NULL;

    construct_metric_key(sk, &key);
    metric = (struct metric_data *)bpf_map_lookup_elem(&map_of_metrics, &key);
    if (!metric) {
        data.conn_open++;
        data.direction = storage->direction;
        int err = bpf_map_update_elem(&map_of_metrics, &key, &data, BPF_NOEXIST);
        if (err) {
            BPF_LOG(ERR, PROBE, "metric_on_connect update failed, err is %d\n", err);
            return;
        }
        goto notify;
    }

    metric->conn_open++;
    metric->direction = storage->direction;
notify:
    report_metrics(sk);
    return;
}

static inline void
metric_on_close(struct bpf_sock *sk, struct bpf_tcp_sock *tcp_sock, struct sock_storage_data *storage)
{
    struct metric_key key = {0};
    struct metric_data data = {0};
    struct metric_data *metric = NULL;

    construct_metric_key(sk, &key);
    metric = (struct metric_data *)bpf_map_lookup_elem(&map_of_metrics, &key);
    if (!metric) {
        // connect failed
        data.direction = storage->direction;
        data.conn_failed++;
        int err = bpf_map_update_elem(&map_of_metrics, &key, &data, BPF_NOEXIST);
        if (err) {
            BPF_LOG(ERR, PROBE, "metric_on_close update failed, err is %d\n", err);
            return;
        }
        goto notify;
    }

    // connect successed & closed
    metric->conn_close++;
    metric->sent_bytes += tcp_sock->delivered;
    metric->received_bytes += tcp_sock->bytes_received;
notify:
    report_metrics(sk);
    return;
}

#endif