/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __BPF_CTX_SOCK_OPS_H
#define __BPF_CTX_SOCK_OPS_H

#include "kmesh_common.h"

typedef struct bpf_sock_ops ctx_buff_t;

#define KMESH_PORG_CALLS sockops

#define DECLARE_VAR_ADDRESS(ctx, name)                                                                                 \
    address_t name = {0};                                                                                              \
    bpf_memset(&name, 0, sizeof(name));                                                                                \
    name.ipv4 = (ctx)->remote_ip4;                                                                                     \
    name.port = (ctx)->remote_port
#define SET_CTX_ADDRESS(ctx, address)                                                                                  \
    (ctx)->replylong[2] = (address)->ipv4;                                                                             \
    (ctx)->replylong[3] = (address)->port
#if OE_23_03
#undef SET_CTX_ADDRESS
#define SET_CTX_ADDRESS(ctx, address)                                                                                  \
    (ctx)->remote_ip4 = (address)->ipv4;                                                                               \
    (ctx)->remote_port = (address)->port
#endif

#endif //__BPF_CTX_SOCK_OPS_H
