// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_ACCESS_LOG_H__
#define __KMESH_BPF_ACCESS_LOG_H__

#include "bpf_common.h"

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

struct tcp_probe_info {
    __u32 type;
    struct bpf_sock_tuple tuple;
    __u32 sent_bytes;
    __u32 received_bytes;
    __u32 conn_success;
    __u32 direction;
    __u32 state; /* tcp state */
    __u32 protocol;
    __u64 duration; // ns
    __u64 close_ns;
    __u32 srtt_us; /* smoothed round trip time << 3 in usecs */
    __u32 rtt_min;
    __u32 mss_cache;     /* Cached effective mss, not including SACKS */
    __u32 total_retrans; /* Total retransmits for entire connection */
    __u32 segs_in;       /* RFC4898 tcpEStatsPerfSegsIn
                          * total number of segments in.
                          */
    __u32 segs_out;      /* RFC4898 tcpEStatsPerfSegsOut
                          * The total number of segments sent.
                          */
    __u32 lost_out;      /* Lost packets			*/
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} map_of_tcp_info SEC(".maps");

static inline void constuct_tuple(struct bpf_sock *sk, struct bpf_sock_tuple *tuple, __u8 direction)
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
    info->sent_bytes = tcp_sock->delivered;
    info->received_bytes = tcp_sock->bytes_received;
    info->srtt_us = tcp_sock->srtt_us;
    info->rtt_min = tcp_sock->rtt_min;
    info->mss_cache = tcp_sock->mss_cache;
    info->total_retrans = tcp_sock->total_retrans;
    info->segs_in = tcp_sock->segs_in;
    info->segs_out = tcp_sock->segs_out;
    info->lost_out = tcp_sock->lost_out;
    return;
}

static inline void
tcp_report(struct bpf_sock *sk, struct bpf_tcp_sock *tcp_sock, struct sock_storage_data *storage, __u32 state)
{
    // struct connect_info *info = NULL;
    struct tcp_probe_info *info = NULL;

    // store tuple
    info = bpf_ringbuf_reserve(&map_of_tcp_info, sizeof(struct tcp_probe_info), 0);
    if (!info) {
        BPF_LOG(ERR, PROBE, "bpf_ringbuf_reserve tcp_report failed\n");
        return;
    }

    constuct_tuple(sk, &info->tuple, storage->direction);
    info->state = state;
    info->direction = storage->direction;
    if (state == BPF_TCP_CLOSE) {
        info->close_ns = bpf_ktime_get_ns();
        info->duration = info->close_ns - storage->connect_ns;
    }
    info->conn_success = storage->connect_success;
    get_tcp_probe_info(tcp_sock, info);
    (*info).type = (sk->family == AF_INET) ? IPV4 : IPV6;
    if (is_ipv4_mapped_addr(sk->dst_ip6)) {
        (*info).type = IPV4;
    }

    bpf_ringbuf_submit(info, 0);
}

#endif