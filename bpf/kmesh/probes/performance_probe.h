// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_PERFORMANCE_MONITOR_H__
#define __KMESH_BPF_PERFORMANCE_MONITOR_H__

#include "bpf_common.h"

static inline void performance_report(struct operation_usage_data *data)
{
    struct operation_usage_data *info = NULL;
    info = bpf_ringbuf_reserve(&kmesh_perf_info, sizeof(struct operation_usage_data), 0);
    if (!info) {
        BPF_LOG(ERR, PROBE, "bpf_ringbuf_reserve map proformance info failed\n");
        return;
    }
    info->start_time = data->start_time;
    info->end_time = data->end_time;
    info->operation_type = data->operation_type;
    info->pid_tgid = data->pid_tgid;
    bpf_ringbuf_submit(info, 0);
}

static inline void observe_on_operation_start(__u32 operation_type, struct kmesh_context *kmesh_ctx)
{
    struct operation_usage_data data = {};
    struct operation_usage_key key = {};
    struct bpf_sock_addr *ctx = kmesh_ctx->ctx;
    __u64 socket_cookie = bpf_get_socket_cookie(ctx);
    key.operation_type = operation_type;
    key.socket_cookie = socket_cookie;
    data.start_time = bpf_ktime_get_ns();
    data.operation_type = operation_type;
    bpf_map_update_elem(&kmesh_perf_map, &key, &data, BPF_ANY);
    return;
}

static inline void observe_on_operation_end(__u32 operation_type, struct kmesh_context *kmesh_ctx)
{
    struct operation_usage_key key = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct bpf_sock_addr *ctx = kmesh_ctx->ctx;
    __u64 socket_cookie = bpf_get_socket_cookie(ctx);
    key.operation_type = operation_type;
    key.socket_cookie = socket_cookie;
    struct operation_usage_data *data = NULL;
    data = bpf_map_lookup_elem(&kmesh_perf_map, &key);
    if (data) {
        data->end_time = bpf_ktime_get_ns();
        data->pid_tgid = pid_tgid;
        performance_report(data);
    }
    bpf_map_delete_elem(&kmesh_perf_map, &key);
    return;
}
#endif