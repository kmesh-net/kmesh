// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_PROBE_H__
#define __KMESH_BPF_PROBE_H__

#include "access_log.h"
#include "metrics.h"
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <linux/sched.h>

#define PAGE_SHIFT 12 // Define PAGE_SHIFT manually

static inline void observe_on_pre_connect(struct bpf_sock *sk)
{
    struct sock_storage_data *storage = NULL;
    if (!sk)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "pre_connect bpf_sk_storage_get failed\n");
        return;
    }

    storage->connect_ns = bpf_ktime_get_ns();
    return;
}

static inline void observe_on_connect_established(struct bpf_sock *sk, __u8 direction)
{
    struct bpf_tcp_sock *tcp_sock = NULL;
    struct sock_storage_data *storage = NULL;
    __u64 flags = (direction == OUTBOUND) ? 0 : BPF_LOCAL_STORAGE_GET_F_CREATE;

    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, flags);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "connect bpf_sk_storage_get failed\n");
        return;
    }

    // INBOUND scenario
    if (direction == INBOUND)
        storage->connect_ns = bpf_ktime_get_ns();
    storage->direction = direction;
    storage->connect_success = true;

    metric_on_connect(sk, tcp_sock, storage);
}

static inline void observe_on_close(struct bpf_sock *sk)
{
    struct bpf_tcp_sock *tcp_sock = NULL;
    struct sock_storage_data *storage = NULL;
    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "close bpf_sk_storage_get failed\n");
        return;
    }

    // report_access_log(sk, tcp_sock, storage);
    metric_on_close(sk, tcp_sock, storage);
}

struct operation_usage_data {
    __u64 start_time;
    __u64 end_time;
    __u32 tid;
    __u64 start_cpu_time;
    __u64 end_cpu_time;
    __u32 operation_type;
    __u64 start_mem;
    __u64 end_mem;
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

struct se_struct_partial {
    __u64 sum_exec_runtime;
};
// Partial definition of task_struct for BPF use
struct task_struct_partial {
    struct se_struct_partial se;
    __u64 utime;
    __u64 stime;
};

static inline void observe_on_operation_start(__u32 operation_type)
{
    BPF_LOG(DEBUG, KMESH, "observe_on_operation_start arg test\n");

    struct operation_usage_data data = {};
    struct operation_usage_key key = {};

    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    key.operation_type = operation_type;
    key.tid = tid;

    data.start_time = bpf_ktime_get_ns();
    BPF_LOG(DEBUG, KMESH, "handle_entry: Start time: %llu ns\n", data.start_time);

    struct task_struct_partial *task = (struct task_struct_partial *)bpf_get_current_task();
    if (task) {
        __u64 utime1 = 0;
        __u64 stime1 = 0;
        int ret_utime = bpf_probe_read_kernel(&utime1, sizeof(utime1), &task->utime);
        int ret_stime = bpf_probe_read_kernel(&stime1, sizeof(stime1), &task->stime);
        __u64 cpu_time = 0;
        if (ret_utime || ret_stime) {
            BPF_LOG(DEBUG, KMESH, "handle_entry: Failed to read utime or stime\n");
        } else {
            cpu_time = utime1 + stime1;
            BPF_LOG(DEBUG, KMESH, "handle_entry: Start CPU time: %llu ns\n", cpu_time);
        }
        data.start_cpu_time = cpu_time;
    } else {
        BPF_LOG(DEBUG, KMESH, "task error\n");
    }

    int ret = bpf_map_update_elem(&performance_data_map, &key, &data, BPF_ANY);
    if (ret) {
        BPF_LOG(DEBUG, KMESH, "handle_entry: Failed to update data_map for TID %d\n", tid);
    } else {
        BPF_LOG(DEBUG, KMESH, "handle_entry: Successfully updated data_map for TID %d\n", tid);
    }

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
        BPF_LOG(DEBUG, KMESH, "handle_exit: Start time: %llu ns\n", data->start_time);
        BPF_LOG(DEBUG, KMESH, "handle_exit: End time: %llu ns\n", data->end_time);

        struct task_struct_partial *task = (struct task_struct_partial *)bpf_get_current_task();

        if (task) {
            __u64 utime1 = 0;
            __u64 stime1 = 0;
            int ret_utime = bpf_probe_read_kernel(&utime1, sizeof(utime1), &task->utime);
            int ret_stime = bpf_probe_read_kernel(&stime1, sizeof(stime1), &task->stime);
            __u64 cpu_time = 0;
            if (ret_utime || ret_stime) {
                BPF_LOG(DEBUG, KMESH, "handle_exit: Failed to read utime or stime\n");
            } else {
                cpu_time = utime1 + stime1;
                BPF_LOG(DEBUG, KMESH, "handle_exit: End CPU time: %llu ns\n", cpu_time);
            }
            data->end_cpu_time = cpu_time;
            BPF_LOG(DEBUG, KMESH, "handle_exit: CPU usage time: %llu ns\n", data->end_cpu_time - data->start_cpu_time);
            __u64 total_time = data->end_time - data->start_time;
            BPF_LOG(DEBUG, KMESH, "TID %d: Total execution time: %llu ns\n", tid, total_time);
            int ret = bpf_map_update_elem(&performance_data_map, &key, data, BPF_ANY);
            if (ret) {
                BPF_LOG(DEBUG, KMESH, "handle_exit: Failed to update data_map for TID %d\n", tid);
            } else {
                BPF_LOG(DEBUG, KMESH, "handle_exit: Successfully updated data_map for TID %d\n", tid);
            }
        } else {
            BPF_LOG(DEBUG, KMESH, "task error\n");
        }
    }

    return;
}
#endif
