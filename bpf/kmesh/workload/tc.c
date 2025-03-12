// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_log.h"
#include "bpf_common.h"
#include "probe.h"

#define TIMER_INTERVAL_NS 1000000000 // 1 seconds (in nanoseconds)

// BPF Timer map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, __u64);
} tcp_conn_last_flush SEC(".maps");

static inline bool is_managed_by_kmesh(struct __sk_buff *skb)
{
    struct manager_key key = {0};

    if (skb->family == AF_INET)
        key.addr.ip4 = skb->local_ip4;
    if (skb->family == AF_INET6) {
        if (is_ipv4_mapped_addr(skb->local_ip6))
            key.addr.ip4 = skb->local_ip6[3];
        else
            IP6_COPY(key.addr.ip6, skb->local_ip6);
    }

    int *value = bpf_map_lookup_elem(&map_of_manager, &key);
    if (!value)
        return false;
    return (*value == 0);
}

static inline void flush_tcp_conns()
{
    struct __u64 *key = NULL, *next_key = NULL;
    struct tcp_probe_info *conn;

    for (int i = 0; i < MAP_SIZE_OF_TCP_CONNS; i++) {
        if (bpf_map_get_next_key(&map_of_tcp_conns, key, next_key) != 0) {
            break;
        }
        conn = bpf_map_lookup_elem(&map_of_tcp_conns, next_key);
        if (!conn) {
            key = next_key;
            continue;
        }

        __u64 now = bpf_ktime_get_ns();
        // Check if connection duration exceeds threshold
        if ((now - conn->start_ns) > LONG_CONN_THRESHOLD_TIME) {
            report_after_threshold_tm(conn);
        }

        key = next_key;
    }
}

// Also trigger's on icmp packets (hence can be used for monitor packet loss)
SEC("tc")
int tc_prog(struct __sk_buff *skb)
{
    if (!is_managed_by_kmesh(skb))
        return 0;

    struct bpf_sock *sk = skb->sk;
    if (!sk) {
        BPF_LOG(ERR, TC, "Failed to get tcp sock\n");
        return 0;
    }

    observe_on_data(sk);

    int key = 0;
    __u64 *last_time = bpf_map_lookup_elem(&tcp_conn_last_flush, &key);
    __u64 now = bpf_ktime_get_ns();

    if (!last_time) {
        __u64 init_time = now;
        // Initialize last flush time if not set
        bpf_map_update_elem(&tcp_conn_last_flush, &key, &init_time, BPF_ANY);
    } else if ((now - *last_time) >= TIMER_INTERVAL_NS) {
        flush_tcp_conns();
        // Update last flush time
        bpf_map_update_elem(&tcp_conn_last_flush, &key, &now, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;