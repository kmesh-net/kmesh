// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_ACCESS_LOG_H__
#define __KMESH_BPF_ACCESS_LOG_H__

#include "bpf_common.h"
#include "config.h"

// direction
enum {
    INVALID_DIRECTION = 0,
    INBOUND = 1,
    OUTBOUND = 2,
};

enum family_type {
    IPV4,
    IPV6,
};

struct orig_dst_info {
    union {
        struct {
            __be32 addr;
            __be16 port;
        } ipv4;
        struct {
            __be32 addr[4];
            __be16 port;
        } ipv6;
    };
};

struct tcp_probe_info {
    __u32 type;
    struct bpf_sock_tuple tuple;
    struct orig_dst_info orig_dst;
    __u32 sent_bytes;     /* Total send bytes from start to last_report_ns */
    __u32 received_bytes; /* Total recv bytes from start to last_report_ns */
    __u32 conn_success;
    __u32 direction;
    __u32 state;    /* tcp state */
    __u64 duration; // ns
    __u64 start_ns;
    __u64 last_report_ns; /*timestamp of the last metrics report*/
    __u32 protocol;
    __u32 srtt_us;       /* smoothed round trip time << 3 in usecs until last_report_ns */
    __u32 rtt_min;       /* min round trip time in usecs until last_report_ns */
    __u32 total_retrans; /* Total retransmits from start to last_report_ns */
    __u32 lost_out;      /* Lost packets from start to last_report_ns	*/
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} map_of_tcp_probe SEC(".maps");

static inline void construct_tuple(struct bpf_sock *sk, struct bpf_sock_tuple *tuple, __u8 direction)
{
    if (direction == OUTBOUND) {
        if (sk->family == AF_INET) {
            tuple->ipv4.saddr = sk->src_ip4;
            tuple->ipv4.daddr = sk->dst_ip4;
            tuple->ipv4.sport = sk->src_port;
            tuple->ipv4.dport = bpf_ntohs(sk->dst_port);
        }
        if (sk->family == AF_INET6) {
            bpf_memcpy(tuple->ipv6.saddr, sk->src_ip6, IPV6_ADDR_LEN);
            bpf_memcpy(tuple->ipv6.daddr, sk->dst_ip6, IPV6_ADDR_LEN);
            tuple->ipv6.sport = sk->src_port;
            tuple->ipv6.dport = bpf_ntohs(sk->dst_port);
        }
    }
    if (direction == INBOUND) {
        if (sk->family == AF_INET) {
            tuple->ipv4.daddr = sk->src_ip4;
            tuple->ipv4.saddr = sk->dst_ip4;
            tuple->ipv4.dport = sk->src_port;
            tuple->ipv4.sport = bpf_ntohs(sk->dst_port);
        }
        if (sk->family == AF_INET6) {
            bpf_memcpy(tuple->ipv6.saddr, sk->dst_ip6, IPV6_ADDR_LEN);
            bpf_memcpy(tuple->ipv6.daddr, sk->src_ip6, IPV6_ADDR_LEN);
            tuple->ipv6.dport = sk->src_port;
            tuple->ipv6.sport = bpf_ntohs(sk->dst_port);
        }
    }

    if (is_ipv4_mapped_addr(tuple->ipv6.daddr)) {
        tuple->ipv4.saddr = tuple->ipv6.saddr[3];
        tuple->ipv4.daddr = tuple->ipv6.daddr[3];
        tuple->ipv4.sport = tuple->ipv6.sport;
        tuple->ipv4.dport = tuple->ipv6.dport;
    }

    return;
}

static inline void get_tcp_probe_info(struct bpf_tcp_sock *tcp_sock, struct tcp_probe_info *info)
{
    info->sent_bytes = tcp_sock->bytes_acked; // bytes_acked means already acked sent bytes
    info->received_bytes = tcp_sock->bytes_received;
    info->srtt_us = tcp_sock->srtt_us;
    info->rtt_min = tcp_sock->rtt_min;
    info->total_retrans = tcp_sock->total_retrans;
    info->lost_out = tcp_sock->lost_out;
    return;
}

// construct_orig_dst_info try to read the dst_info from map_of_sock_storage first
// if not found, use the tuple info for orig_dst
static inline void
construct_orig_dst_info(struct bpf_sock *sk, struct sock_storage_data *storage, struct tcp_probe_info *info)
{
    if (sk->family == AF_INET) {
        info->orig_dst.ipv4.addr = storage->sk_tuple.ipv4.daddr;
        info->orig_dst.ipv4.port = bpf_ntohs(storage->sk_tuple.ipv4.dport);
    } else {
        bpf_memcpy(info->orig_dst.ipv6.addr, storage->sk_tuple.ipv6.daddr, IPV6_ADDR_LEN);
        info->orig_dst.ipv6.port = bpf_ntohs(storage->sk_tuple.ipv6.dport);
    }

    if (is_ipv4_mapped_addr(info->orig_dst.ipv6.addr)) {
        info->orig_dst.ipv4.addr = info->orig_dst.ipv6.addr[3];
        info->orig_dst.ipv4.port = info->orig_dst.ipv6.port;
    }
}

static inline void
tcp_report(struct bpf_sock *sk, struct bpf_tcp_sock *tcp_sock, struct sock_storage_data *storage, __u32 state)
{
    struct tcp_probe_info *info = NULL;

    // store tuple
    info = bpf_ringbuf_reserve(&map_of_tcp_probe, sizeof(struct tcp_probe_info), 0);
    if (!info) {
        BPF_LOG(ERR, PROBE, "bpf_ringbuf_reserve tcp_report failed\n");
        return;
    }

    construct_tuple(sk, &info->tuple, storage->direction);
    info->start_ns = storage->connect_ns;
    info->state = state;
    info->direction = storage->direction;
    info->conn_success = storage->connect_success;
    get_tcp_probe_info(tcp_sock, info);
    (*info).type = (sk->family == AF_INET) ? IPV4 : IPV6;
    if (is_ipv4_mapped_addr(sk->dst_ip6)) {
        (*info).type = IPV4;
    }

    construct_orig_dst_info(sk, storage, info);
    info->last_report_ns = bpf_ktime_get_ns();
    info->duration = info->last_report_ns - storage->connect_ns;
    storage->last_report_ns = info->last_report_ns;
    bpf_ringbuf_submit(info, 0);
}

#endif