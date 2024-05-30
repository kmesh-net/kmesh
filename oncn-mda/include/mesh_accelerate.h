/*
 * Copyright 2023 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Description: the file define the ebpf map
 */

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

struct bpf_map_def SEC("maps") SOCK_OPS_MAP_NAME = {
    .type = BPF_MAP_TYPE_SOCKHASH,
    .key_size = sizeof(struct sock_key),
    .value_size = sizeof(int),
    .max_entries = SKOPS_MAP_SIZE,
    .map_flags = 0,
};

struct bpf_map_def SEC("maps") SOCK_PARAM_MAP_NAME = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct sock_param),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") SOCK_OPS_PROXY_MAP_NAME = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sock_key),
    .value_size = sizeof(struct sock_key),
    .max_entries = SKOPS_MAP_SIZE,
    .map_flags = 0,
};

#if MDA_GID_UID_FILTER
struct bpf_map_def SEC("maps") SOCK_OPS_HELPER_MAP_NAME = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sock_key),
    .value_size = sizeof(struct uid_gid_info),
    .max_entries = SKOPS_MAP_SIZE,
    .map_flags = 0,
};
#endif

struct bpf_map_def SEC("maps") SOCK_DUMP_MAP_I_NAME = {
    .type = BPF_MAP_TYPE_QUEUE,
    .key_size = 0,
    .value_size = sizeof(struct dump_data),
    .max_entries = DUMP_QUEUE_LENGTH,
    .map_flags = 0,
};

struct bpf_map_def SEC("maps") SOCK_DUMP_CPU_ARRAY_NAME = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct dump_data),
    .max_entries = 1,
};

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
