// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_ACCESS_LOG_H__
#define __KMESH_BPF_ACCESS_LOG_H__
#define LONG_CONN_THRESHOLD_TIME (5 * 1000000000ULL) // 5s

#include "bpf_common.h"
#include "config.h"
#include "encoder.h"
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
    __u64 conn_id;        /* sock_cookie */
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
    __uint(max_entries, 1 << 24 /* 16 mb*/);
} map_of_tcp_probe SEC(".maps");

// Ebpf map to store active tcp connections
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64); // use sock_cookie as key
    __type(value, struct tcp_probe_info);
    __uint(max_entries, MAP_SIZE_OF_TCP_CONNS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_of_tcp_conns SEC(".maps");

// Ebpf array map to store the the lists of socket_ids
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAP_SIZE_OF_TCP_CONNS);
} map_of_soc_id SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} map_of_soc_id_counter SEC(".maps");

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

// construct_orig_dst_info try to read the dst_info from map_of_orig_dst first
// if not found, use the tuple info for orig_dst
static inline void construct_orig_dst_info(struct bpf_sock *sk, struct tcp_probe_info *info)
{
    __u64 *current_sk = (__u64 *)sk;
    struct bpf_sock_tuple *dst;
    dst = bpf_map_lookup_elem(&map_of_orig_dst, &current_sk);

    // when dst not found, metric controller will read orig dst from actual dst
    if (!dst) {
        return;
    }

    if (sk->family == AF_INET) {
        info->orig_dst.ipv4.addr = dst->ipv4.daddr;
        info->orig_dst.ipv4.port = bpf_ntohs(dst->ipv4.dport);
    } else {
        bpf_memcpy(info->orig_dst.ipv6.addr, dst->ipv6.daddr, IPV6_ADDR_LEN);
        info->orig_dst.ipv6.port = bpf_ntohs(dst->ipv6.dport);
    }

    if (is_ipv4_mapped_addr(info->orig_dst.ipv6.addr)) {
        info->orig_dst.ipv4.addr = info->orig_dst.ipv6.addr[3];
        info->orig_dst.ipv4.port = info->orig_dst.ipv6.port;
    }
}

// Store new tcp connection in map_of_tcp_conns and report the info to ring-buff for the first time
static inline void record_report_tcp_conn_info(
    struct bpf_sock *sk, struct bpf_tcp_sock *tcp_sock, struct sock_storage_data *storage, __u32 state)
{
    struct tcp_probe_info info_vals = {0};
    struct tcp_probe_info *info = NULL;
    info = bpf_ringbuf_reserve(&map_of_tcp_probe, sizeof(struct tcp_probe_info), 0);
    if (!info) {
        BPF_LOG(ERR, PROBE, "bpf_ringbuf_reserve tcp_report failed\n");
        return;
    }
    __u64 now = bpf_ktime_get_ns();

    info_vals.conn_id = storage->sock_cookie;
    info_vals.start_ns = storage->connect_ns;
    info_vals.last_report_ns = now;
    construct_tuple(sk, &info_vals.tuple, storage->direction);

    info_vals.state = state;
    info_vals.direction = storage->direction;
    info_vals.duration = now - info->start_ns;
    info_vals.conn_success = storage->connect_success;
    info_vals.sent_bytes = tcp_sock->delivered;
    info_vals.received_bytes = tcp_sock->bytes_received;
    info_vals.srtt_us = tcp_sock->srtt_us;
    info_vals.rtt_min = tcp_sock->rtt_min;
    info_vals.total_retrans = tcp_sock->total_retrans;
    info_vals.lost_out = tcp_sock->lost_out;

    info_vals.type = (sk->family == AF_INET) ? IPV4 : IPV6;
    if (is_ipv4_mapped_addr(sk->dst_ip6)) {
        info_vals.type = IPV4;
    }

    construct_orig_dst_info(sk, &info_vals);
    __builtin_memcpy(info, &info_vals, sizeof(struct tcp_probe_info));
    bpf_map_update_elem(&map_of_tcp_conns, &storage->sock_cookie, &info_vals, BPF_ANY);
    bpf_ringbuf_submit(info, 0);
    __u32 zero = 0;
    __u32 *index = bpf_map_lookup_elem(&map_of_soc_id_counter, &zero);
    if (index && *index < MAP_SIZE_OF_TCP_CONNS) {
        bpf_map_update_elem(&map_of_soc_id, index, &storage->sock_cookie, BPF_ANY);
        *index += 1;
        bpf_map_update_elem(&map_of_soc_id_counter, &zero, index, BPF_ANY);
    }
}

static inline void
refresh_tcp_conn_info_on_state_change(struct bpf_tcp_sock *tcp_sock, struct sock_storage_data *storage, __u32 state)
{
    struct tcp_probe_info *info = NULL;
    struct tcp_probe_info *info_vals = bpf_map_lookup_elem(&map_of_tcp_conns, &storage->sock_cookie);
    if (!info_vals) {
        BPF_LOG(ERR, PROBE, "lookup in map_of_tcp_conns failed\n");
        return;
    }
    __u64 now = bpf_ktime_get_ns();
    info_vals->state = state;
    info_vals->duration = now - info_vals->start_ns;
    info_vals->sent_bytes = tcp_sock->delivered;
    info_vals->received_bytes = tcp_sock->bytes_received;
    info_vals->srtt_us = tcp_sock->srtt_us;
    info_vals->rtt_min = tcp_sock->rtt_min;
    info_vals->total_retrans = tcp_sock->total_retrans;
    info_vals->lost_out = tcp_sock->lost_out;

    // Remove tcp connection from map_of_tcp_conns when the conn is closed and report the info to ring-buff
    if (state == BPF_TCP_CLOSE) {
        info_vals->last_report_ns = now;
        info = bpf_ringbuf_reserve(&map_of_tcp_probe, sizeof(struct tcp_probe_info), 0);
        if (!info) {
            BPF_LOG(ERR, PROBE, "bpf_ringbuf_reserve tcp_report failed\n");
            return;
        }

        __builtin_memcpy(info, info_vals, sizeof(struct tcp_probe_info));
        bpf_map_delete_elem(&map_of_tcp_conns, &storage->sock_cookie);
        bpf_ringbuf_submit(info, 0);
    }
}

static inline void refresh_tcp_conn_info(struct bpf_tcp_sock *tcp_sock, struct sock_storage_data *storage)
{
    struct tcp_probe_info *info_vals = bpf_map_lookup_elem(&map_of_tcp_conns, &storage->sock_cookie);
    if (!info_vals) {
        return;
    }
    __u64 now = bpf_ktime_get_ns();
    info_vals->duration = now - info_vals->start_ns;
    info_vals->sent_bytes = tcp_sock->delivered;
    info_vals->received_bytes = tcp_sock->bytes_received;
    info_vals->srtt_us = tcp_sock->srtt_us;
    info_vals->rtt_min = tcp_sock->rtt_min;
    info_vals->total_retrans = tcp_sock->total_retrans;
    info_vals->lost_out = tcp_sock->lost_out;
}

#endif