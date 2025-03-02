// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <bpf/bpf_tracing.h>
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
    __type(value, struct bpf_timer);
} tcp_conn_flush_timer SEC(".maps");

static void flush_tcp_conns()
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

    // Re-arm the timer for the next execution
    int key_idx = 0;
    struct bpf_timer *timer = bpf_map_lookup_elem(&tcp_conn_flush_timer, &key_idx);
    if (timer) {
        bpf_timer_start(timer, TIMER_INTERVAL_NS, 0);
    }
}

static int timer_callback(struct bpf_timer *timer)
{
    flush_tcp_conns();
    return 0;
}

// Also trigger's on icmp packets (hence can be used for monitor packet loss)
SEC("tc")
int tc_prog(struct __sk_buff *skb)
{
    int key = 0;
    struct bpf_timer *timer = bpf_map_lookup_elem(&tcp_conn_flush_timer, &key);
    if (!timer) {
        BPF_LOG(ERR, TIMER, "Failed to lookup tcp timer\n");
    } else {
        // Initialize and start timer
        bpf_timer_init(timer, &tcp_conn_flush_timer, 1);
        bpf_timer_set_callback(timer, timer_callback);
        bpf_timer_start(timer, TIMER_INTERVAL_NS, 0);
    }

    struct bpf_tcp_sock *sk = skb->sk;
    if (!sk) {
        BPF_LOG(ERR, TC, "Failed to get tcp sock\n");
        return 0;
    }

    observe_on_data(sk);
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;