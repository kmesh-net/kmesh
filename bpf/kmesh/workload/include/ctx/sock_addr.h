/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __BPF_CTX_SOCK_ADDR_H
#define __BPF_CTX_SOCK_ADDR_H

typedef enum {
    PROTOCOL_TCP = 0,
    PROTOCOL_UDP,
} protocol_t;

typedef struct bpf_sock_addr ctx_buff_t;

#define DECLARE_FRONTEND_KEY(ctx, key)                                                                                 \
    frontend_key key = {0};                                                                                            \
    key.ipv4 = (ctx)->user_ip4

#define SET_CTX_ADDRESS(ctx, address)                                                                                  \
    (ctx)->user_ip4 = (address).ipv4;                                                                                  \
    (ctx)->user_port = (address).port

#endif //__BPF_CTX_SOCK_ADDR_H
