// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <bpf/bpf_tracing.h> 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_log.h"
#include "bpf_common.h"
#include "probe.h"
#include "tcp_long_conn_probe.h"

#define TIMER_INTERVAL_NS 1000000000 // 1 seconds (in nanoseconds)


// BPF Timer map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct bpf_timer);
} long_conn_flush_timer SEC(".maps");


static void flush_long_conns()
{
    struct bpf_sock *key = NULL, *next_key = NULL;
    struct long_tcp_conns *conn;

    for(int i = 0; i < MAP_SIZE_OF_LONG_TCP_CONN; i++) {
        if(bpf_map_get_next_key(&map_of_long_tcp_conns, key, next_key) != 0) {
           break;
        }
        conn = bpf_map_lookup_elem(&map_of_long_tcp_conns, next_key);
        if (!conn) {
                key = next_key;
                continue;
        }
        
        __u64 now = bpf_ktime_get_ns();
        // Check if connection duration exceeds threshold
        if ((now - conn->start_ns) > LONG_CONN_THRESHOLD_TIME) {
            obeserve_long_conn_tcp(conn->sk);
        }

        key = next_key;
    }

    // Re-arm the timer for the next execution
    int key_idx = 0;
    struct bpf_timer *timer = bpf_map_lookup_elem(&long_conn_flush_timer, &key_idx);
    if (timer) {
        bpf_timer_start(timer, TIMER_INTERVAL_NS, 0);
    }
}

static int timer_callback(struct bpf_timer *timer)
{
    flush_long_conns();
    return 0;
}

SEC("tc")
int init_tcp_long_conn_flush_timer(struct __sk_buff *skb)
{
    int key = 0;
    struct bpf_timer *timer = bpf_map_lookup_elem(&long_conn_flush_timer, &key);
    if (!timer)
        return 0;

    // Initialize and start timer
    bpf_timer_init(timer, &long_conn_flush_timer, 1);
    bpf_timer_set_callback(timer, timer_callback);
    bpf_timer_start(timer, TIMER_INTERVAL_NS, 0);

    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;