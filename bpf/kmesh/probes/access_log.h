// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_ACCESS_LOG_H__
#define __KMESH_BPF_ACCESS_LOG_H__

#include "bpf_common.h"

// access log
enum {
    INVALID_DIRECTION = 0,
    INBOUND = 1,
    OUTBOUND = 2,
};

struct access_log {
    struct bpf_sock_tuple tuple;
    __u64 duration; // ns
    __u64 close_ns;
    __u32 family;
    __u32 protocol;
    __u8 direction;
    __u32 sent_bytes;
    __u32 received_bytes;
    __u32 conn_success;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} map_of_access_log SEC(".maps");

static inline void constuct_tuple(struct bpf_sock *sk, struct bpf_sock_tuple *tuple)
{
    if (sk->family == AF_INET) {
        tuple->ipv4.saddr = sk->src_ip4;
        tuple->ipv4.daddr = sk->dst_ip4;
        tuple->ipv4.sport = sk->src_port;
        tuple->ipv4.dport = sk->dst_port;
    } else {
        bpf_memcpy(tuple->ipv6.saddr, sk->src_ip6, IPV6_ADDR_LEN);
        bpf_memcpy(tuple->ipv6.daddr, sk->dst_ip6, IPV6_ADDR_LEN);
        tuple->ipv6.sport = sk->src_port;
        tuple->ipv6.dport = sk->dst_port;
    }
    return;
}

static inline void
report_access_log(struct bpf_sock *sk, struct bpf_tcp_sock *tcp_sock, struct sock_storage_data *storage)
{
    struct access_log *log = NULL;

    // store tuple
    log = bpf_ringbuf_reserve(&map_of_access_log, sizeof(struct access_log), 0);
    if (!log) {
        BPF_LOG(ERR, PROBE, "bpf_ringbuf_reserve access_log failed\n");
        return;
    }

    constuct_tuple(sk, &log->tuple);
    log->direction = storage->direction;
    log->close_ns = bpf_ktime_get_ns();
    log->duration = log->close_ns - storage->connect_ns;
    log->sent_bytes = tcp_sock->delivered;
    log->received_bytes = tcp_sock->bytes_received;
    log->conn_success = storage->connect_success;

    bpf_ringbuf_submit(log, 0);
}

#endif