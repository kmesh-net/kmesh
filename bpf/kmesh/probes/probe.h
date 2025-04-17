// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_PROBE_H__
#define __KMESH_BPF_PROBE_H__

#include "tcp_probe.h"
#include "performance_probe.h"

#define LONG_CONN_THRESHOLD_TIME (5 * 1000000000ULL) // 5s

volatile __u32 enable_monitoring = 0;

static inline bool is_monitoring_enable()
{
    return enable_monitoring == 1;
}

static inline void observe_on_pre_connect(struct bpf_sock *sk)
{
    struct sock_storage_data *storage = NULL;
    if (!sk)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "pre_connect bpf_sk_storage_get failed\n");
        return;
    }

    storage->connect_ns = bpf_ktime_get_ns();
    return;
}

static inline void observe_on_connect_established(struct bpf_sock *sk, __u8 direction)
{
    if (!is_monitoring_enable()) {
        return;
    }

    struct bpf_tcp_sock *tcp_sock = NULL;
    struct sock_storage_data *storage = NULL;
    __u64 flags = (direction == OUTBOUND) ? 0 : BPF_LOCAL_STORAGE_GET_F_CREATE;

    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, flags);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "on connect: bpf_sk_storage_get failed\n");
        return;
    }

    // INBOUND scenario
    if (direction == INBOUND)
        storage->connect_ns = bpf_ktime_get_ns();
    storage->direction = direction;
    storage->connect_success = true;
    tcp_report(sk, tcp_sock, storage, BPF_TCP_ESTABLISHED);
}

static inline void observe_on_close(struct bpf_sock *sk)
{
    if (!is_monitoring_enable()) {
        return;
    }
    struct bpf_tcp_sock *tcp_sock = NULL;
    struct sock_storage_data *storage = NULL;
    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "on close: bpf_sk_storage_get failed\n");
        return;
    }

    tcp_report(sk, tcp_sock, storage, BPF_TCP_CLOSE);
}

static inline void observe_on_data(struct bpf_sock *sk)
{
    struct bpf_tcp_sock *tcp_sock = NULL;
    struct sock_storage_data *storage = NULL;
    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        return;
    }
    __u64 now = bpf_ktime_get_ns();
    if ((storage->last_report_ns != 0) && (now - storage->last_report_ns > LONG_CONN_THRESHOLD_TIME)) {
        tcp_report(sk, tcp_sock, storage, BPF_TCP_ESTABLISHED);
    }
}
#endif