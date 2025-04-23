/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __BPF_CTX_SOCK_OPS_H
#define __BPF_CTX_SOCK_OPS_H

#include "kmesh_common.h"

typedef struct bpf_sock_ops ctx_buff_t;

#define KMESH_PORG_CALLS sockops

// tail_call map dont support pinning when shared by different bpf types, so define different name in sockops & sockconn
// this is making the map named km_cgrptailcall in sock_addr prog
// And below make another map km_skopstailcall in sock_ops prog.
// So the code can be reused kmesh_tail_call by different progs without passing in the map name
#define map_of_tail_call_prog km_skopstailcall

#define DECLARE_VAR_ADDRESS(ctx, name)                                                                                 \
    address_t name = {0};                                                                                              \
    bpf_memset(&name, 0, sizeof(name));                                                                                \
    name.ipv4 = (ctx)->remote_ip4;                                                                                     \
    name.port = (ctx)->remote_port

#define SET_CTX_ADDRESS(ctx, address)                                                                                  \
    (ctx)->replylong[2] = (address)->ipv4;                                                                             \
    (ctx)->replylong[3] = (address)->port

#define MARK_REJECTED(ctx)                                                                                             \
    BPF_LOG(DEBUG, KMESH, "mark reject\n");                                                                            \
    (ctx)->replylong[2] = 0;                                                                                           \
    (ctx)->replylong[3] = 0

#endif //__BPF_CTX_SOCK_OPS_H
