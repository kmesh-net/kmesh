/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef _KMESH_WORKLOAD_TAIL_CALL_H_
#define _KMESH_WORKLOAD_TAIL_CALL_H_

#include "workload_common.h"

#define MAP_SIZE_OF_TAIL_CALL_PROG 8

typedef struct bpf_sock_addr ctx_buff_t;

typedef enum {
    TAIL_CALL_CONNECT4_INDEX = 0,
    TAIL_CALL_CONNECT6_INDEX,
    TAIL_CALL_PORT_MATCH,
    TAIL_CALL_SRCIP_MATCH,
    TAIL_CALL_DSTIP_MATCH,
} workload_tail_call_index_t;

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAP_SIZE_OF_TAIL_CALL_PROG);
    __uint(map_flags, 0);
} map_of_tail_call_prog SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAP_SIZE_OF_TAIL_CALL_PROG);
    __uint(map_flags, 0);
} map_of_tail_call_prog_for_xdp SEC(".maps");

static inline void kmesh_workload_tail_call(ctx_buff_t *ctx, const __u32 index)
{
    bpf_tail_call(ctx, &map_of_tail_call_prog, index);
}

#endif