// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <bpf/bpf_tracing.h> 
#include <linux/perf_event.h> 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_log.h"
#include "bpf_common.h"
#include "probe.h"
#include "tcp_long_conn_probe.h"

// Flush Function: Periodically invoked via a perf event.
// Iterates over the map_of_long_tcp_conns and submits events for connections that have been open longer than LONG_CONN_THRESHOLD_NS.
SEC("perf_event/flush")
int flush_long_conns(struct bpf_perf_event_data *ctx) {
    struct bpf_sock *key = NULL, *next_key = NULL;
    struct long_tcp_conns *conn;

    __u64 now = bpf_ktime_get_ns();

    while (bpf_map_get_next_key(&map_of_long_tcp_conns, key, next_key) == 0) {
        conn = bpf_map_lookup_elem(&map_of_long_tcp_conns, next_key);
        if (!conn) {
            key = next_key;
            continue;
        }

        // Check if connection duration exceeds threshold
        if ((now - conn->start_ns) > LONG_CONN_THRESHOLD_TIME) {
            obeserve_long_conn_tcp(conn->sk, now);
        }

        key = next_key;
    }
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;