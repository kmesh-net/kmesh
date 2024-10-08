// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_PERFORMANCE_MONITOR_H__
#define __KMESH_BPF_PERFORMANCE_MONITOR_H__

#include "bpf_common.h"

enum {
    SOCK_TRAFFIC_CONTROL = 1,
    XDP_SHUTDOWN = 2,
    ENABLE_ENCODING_METADATA = 3,
};

struct operation_usage_data {
    __u64 start_time;
    __u64 end_time;
    __u32 operation_type;
};

struct operation_usage_key {
    __u32 tid;
    __u32 operation_type;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct operation_usage_key);
    __type(value, struct operation_usage_data);
    __uint(max_entries, 1024);
} performance_data_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} map_perf_info SEC(".maps");

static inline void performance_report(struct operation_usage_data *data)
{
    struct operation_usage_data *info = NULL;
    info = bpf_ringbuf_reserve(&map_perf_info, sizeof(struct operation_usage_data), 0);
    if (!info) {
        BPF_LOG(ERR, PROBE, "bpf_ringbuf_reserve map proformance info failed\n");
        return;
    }
    info->start_time = data->start_time;
    info->end_time = data->end_time;
    info->operation_type = data->operation_type;
    bpf_ringbuf_submit(info, 0);
}

static inline void observe_on_operation_start(__u32 operation_type)
{
    struct operation_usage_data data = {};
    struct operation_usage_key key = {};
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    key.operation_type = operation_type;
    key.tid = tid;
    data.start_time = bpf_ktime_get_ns();
    data.operation_type = operation_type;
    bpf_map_update_elem(&performance_data_map, &key, &data, BPF_ANY);
    return;
}

static inline void observe_on_operation_end(__u32 operation_type)
{
    struct operation_usage_key key = {};
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    key.tid = tid;
    key.operation_type = operation_type;
    struct operation_usage_data *data = NULL;
    data = bpf_map_lookup_elem(&performance_data_map, &key);
    if (data) {
        data->end_time = bpf_ktime_get_ns();
        performance_report(data);
    }
    return;
}
#endif