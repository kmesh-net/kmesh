/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __BPF_CTX_SOCK_ADDR_H
#define __BPF_CTX_SOCK_ADDR_H

typedef struct bpf_sock_addr ctx_buff_t;

// clang-format off
#define KMESH_PORG_CALLS    cgroup/connect4
// clang-format on

// tail_call map dont support pinning when shared by different bpf types, so define different name in sockops & sockconn
// this is making the map named km_cgrptailcall in sock_addr prog
// And below make another map km_skopstailcall in sock_ops prog.
// So the code can be reused kmesh_tail_call by different progs without passing in the map name
#define map_of_tail_call_prog km_cgrptailcall

#define DECLARE_VAR_ADDRESS(ctx, name)                                                                                 \
    address_t name = {0};                                                                                              \
    name.ipv4 = (ctx)->user_ip4;                                                                                       \
    name.port = (ctx)->user_port;                                                                                      \
    name.protocol =                                                                                                    \
        ((ctx)->protocol == IPPROTO_TCP) ? CORE__SOCKET_ADDRESS__PROTOCOL__TCP : CORE__SOCKET_ADDRESS__PROTOCOL__UDP

#define SET_CTX_ADDRESS(ctx, address)                                                                                  \
    (ctx)->user_ip4 = (address)->ipv4;                                                                                 \
    (ctx)->user_port = (address)->port

#define MARK_REJECTED(ctx)

#endif //__BPF_CTX_SOCK_ADDR_H
