// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include "bpf_common.h"
#include "tcp_probe.h"
#include "bpf_log.h"
#include "config.h"

#define LONG_CONN_THRESHOLD_TIME (5 * 1000000000ULL) // 5s

struct long_tcp_conns {
    struct bpf_sock *sk;
    __u64 start_ns;
    __u64 last_report_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bpf_sock *);
    __type(value, struct long_tcp_conns);
    __uint(max_entries, MAP_SIZE_OF_LONG_TCP_CONN);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_of_long_tcp_conns SEC(".maps");

// BPF ring buffer to output events to user space.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB ring buffer
} long_tcp_conns_events SEC(".maps");


static inline void record_long_tcp_conn(struct bpf_sock *sk)
{
    struct long_tcp_conns conn = {0};
    conn.sk = sk;
    conn.start_ns = bpf_ktime_get_ns();
    conn.last_report_ns = conn.start_ns;
    bpf_map_update_elem(&map_of_long_tcp_conns, &sk, &conn, BPF_ANY);
}

static inline void remove_long_tcp_conn(struct bpf_sock *sk)
{
    struct bpf_sock *lookup;

    lookup = (struct bpf_sock *)bpf_map_lookup_elem(&map_of_long_tcp_conns, &sk);
    if (lookup) {
        bpf_map_delete_elem(&map_of_long_tcp_conns, &sk);
    }
}

static inline void report_tcp_conn(struct bpf_sock *sk, __u64 now, struct bpf_tcp_sock *tcp_sock, struct sock_storage_data *storage, __u32 state) {
    struct tcp_probe_info *info = NULL;
    struct long_tcp_conns *conn;

    conn = (struct long_tcp_conns *)bpf_map_lookup_elem(&map_of_long_tcp_conns, &sk);
    if (!conn) {
        return;
    }

    if (now - conn->last_report_ns < LONG_CONN_THRESHOLD_TIME) {
        return;
    }

    info = bpf_ringbuf_reserve(&long_tcp_conns_events, sizeof(struct tcp_probe_info), 0);
    if (!info) {
        BPF_LOG(ERR, PROBE, "bpf_ringbuf_reserve long_tcp_conns_events failed\n");
        return;
    }
    
    conn->last_report_ns = now;
    info->start_ns = conn->start_ns;
    info->last_report_ns = conn->last_report_ns;
    constuct_tuple(sk, &info->tuple, storage->direction);
    info->state = state;
    info->direction = storage->direction;
    info->duration = now - conn->start_ns;
    info->conn_success = storage->connect_success;
    get_tcp_probe_info(tcp_sock, info);
    (*info).type = (sk->family == AF_INET) ? IPV4 : IPV6;
    if (is_ipv4_mapped_addr(sk->dst_ip6)) {
        (*info).type = IPV4;
    }

    construct_orig_dst_info(sk, info);
    bpf_ringbuf_submit(info, 0);
}
