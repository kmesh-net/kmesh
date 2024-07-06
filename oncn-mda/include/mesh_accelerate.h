/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef MESH_ACCELERATING_H
#define MESH_ACCELERATING_H

#include <errno.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "data.h"

enum bpf_loglevel {
    BPF_LOG_ERROR = 0,
    BPF_LOG_WARN,
    BPF_LOG_INFO,
    BPF_LOG_DEBUG,
};

#define BPF_LOGLEVEL BPF_LOG_ERROR

#if OE_23_03
#define GET_SKOPS_REMOTE_PORT(sk_ops) (__u16)((sk_ops)->remote_port)
#else
#define GET_SKOPS_REMOTE_PORT(sk_ops) (__u16)((sk_ops)->remote_port >> 16)
#endif

#define GET_SKOPS_LOCAL_PORT(sk_ops) (__u16)((sk_ops)->local_port)

#ifndef bpf_printk
#define bpf_printk(fmt, ...)                                                                                           \
    ({                                                                                                                 \
        char ____fmt[] = fmt;                                                                                          \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                                                     \
    })
#endif

#define bpf_log(l, f, ...)                                                                                             \
    do {                                                                                                               \
        if (BPF_LOG_##l <= BPF_LOGLEVEL)                                                                               \
            bpf_printk("[oncn-mda " #l "] " f "", ##__VA_ARGS__);                                                      \
    } while (0)

#ifndef force_read
#define force_read(X) (*(volatile typeof(X) *)&(X))
#endif

#define SO_ORIGINAL_DST 800

#define FILTER_PASS   true
#define FILTER_RETURN false

#define UID_LENGTH       32
#define FORMAT_IP_LENGTH 16

#define LOOPBACK_ADDR 16777343

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __type(key, struct sock_key);
    __type(value, int);
    __uint(max_entries, SKOPS_MAP_SIZE);
    __uint(map_flags, 0);
} SOCK_OPS_MAP_NAME SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct sock_param);
    __uint(max_entries, 1);
} SOCK_PARAM_MAP_NAME SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sock_key);
    __type(value, struct sock_key);
    __uint(max_entries, SKOPS_MAP_SIZE);
    __uint(map_flags, 0);
} SOCK_OPS_PROXY_MAP_NAME SEC(".maps");

#if MDA_GID_UID_FILTER
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sock_key);
    __type(value, struct uid_gid_info);
    __uint(max_entries, SKOPS_MAP_SIZE);
    __uint(map_flags, 0);
} SOCK_OPS_HELPER_MAP_NAME SEC(".maps");
#endif

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(key_size, 0);
    __type(value, struct dump_data);
    __uint(max_entries, DUMP_QUEUE_LENGTH);
    __uint(map_flags, 0);
} SOCK_DUMP_MAP_I_NAME SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct dump_data);
    __uint(max_entries, 1);
} SOCK_DUMP_CPU_ARRAY_NAME SEC(".maps");

#if MDA_LOOPBACK_ADDR
static inline void set_netns_cookie(void *const ctx, struct sock_key *const key)
{
    if (key->sip4 != LOOPBACK_ADDR || key->dip4 != LOOPBACK_ADDR)
        key->netns_cookie = 0;
    else
        key->netns_cookie = bpf_get_netns_cookie(ctx);
    return;
}
#endif

#endif
