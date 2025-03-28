// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_PROBE_H__
#define __KMESH_BPF_PROBE_H__

#include "tcp_probe.h"
#include "performance_probe.h"

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

static inline void observe_on_connect_established(struct bpf_sock *sk, __u64 sock_cookie, __u8 direction)
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
    storage->sock_cookie = sock_cookie;
    record_report_tcp_conn_info(sk, tcp_sock, storage, BPF_TCP_ESTABLISHED);
}

static inline void observe_on_status_change(struct bpf_sock *sk, __u32 state)
{
    if (!is_monitoring_enable()) {
        return;
    }

    if (state == BPF_TCP_ESTABLISHED) {
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
        BPF_LOG(ERR, PROBE, "on status: bpf_sk_storage_get failed\n");
        return;
    }

    refresh_tcp_conn_info_on_state_change(tcp_sock, storage, state);
    if (state == BPF_TCP_CLOSE) {
        bpf_sk_storage_delete(&map_of_sock_storage, sk);
    }
}

static inline void observe_on_retransmit(struct bpf_sock *sk)
{
    if (!is_monitoring_enable()) {
        return;
    }
    struct sock_storage_data *storage = NULL;
    struct bpf_tcp_sock *tcp_sock = NULL;
    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "on retransmit: bpf_sk_storage_get failed\n");
        return;
    }
    refresh_tcp_conn_info_on_retransmit_rtt(tcp_sock, storage);
}

// observe_on_rtt is called when the RTT of a connection changes
static inline void observe_on_rtt(struct bpf_sock *sk)
{
    if (!is_monitoring_enable()) {
        return;
    }

    struct sock_storage_data *storage = NULL;
    struct bpf_tcp_sock *tcp_sock = NULL;

    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;
    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "on rtt: bpf_sk_storage_get failed\n");
        return;
    }
    refresh_tcp_conn_info_on_retransmit_rtt(tcp_sock, storage);
}

static inline void observe_on_send(struct bpf_sock *sk, __u32 size)
{
    if (!is_monitoring_enable()) {
        return;
    }
    struct sock_storage_data *storage = NULL;

    if (!sk)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "on rtt: bpf_sk_storage_get failed\n");
        return;
    }
    refresh_tcp_conn_info_on_send(storage, size);
}

static inline void report_after_threshold_tm(struct bpf_sock *sk)
{
    if (!is_monitoring_enable()) {
        return;
    }

    struct sock_storage_data *storage = NULL;
    if (!sk)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "on rtt: bpf_sk_storage_get failed\n");
        return;
    }

    struct tcp_probe_info *info_vals = bpf_map_lookup_elem(&map_of_tcp_conns, &storage->sock_cookie);
    if (!info_vals) {
        return;
    }

    __u64 now = bpf_ktime_get_ns();
    if ((now - info_vals->last_report_ns) > LONG_CONN_THRESHOLD_TIME) {
        struct tcp_probe_info *info = bpf_ringbuf_reserve(&map_of_tcp_probe, sizeof(struct tcp_probe_info), 0);
        if (!info) {
            BPF_LOG(ERR, PROBE, "bpf_ringbuf_reserve tcp_report failed\n");
            return;
        }

        info_vals->last_report_ns = now;
        info_vals->duration = now - info_vals->start_ns;
        __builtin_memcpy(info, info_vals, sizeof(struct tcp_probe_info));
        bpf_ringbuf_submit(info, 0);
    }
}

#endif