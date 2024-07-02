/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __BPF_CTX_SOCK_ADDR_H
#define __BPF_CTX_SOCK_ADDR_H

typedef enum {
    PROTOCOL_TCP = 0,
    PROTOCOL_UDP,
} protocol_t;

typedef struct bpf_sock_addr ctx_buff_t;

#define DECLARE_FRONTEND_KEY(ctx, ctx_vip, key)                                                                        \
    frontend_key key = {0};                                                                                            \
    if (ctx->user_family == AF_INET)                                                                                   \
        key.addr.ip4 = (ctx_vip)->ip4;                                                                                 \
    else                                                                                                               \
        bpf_memcpy(key.addr.ip6, (ctx_vip)->ip6, IPV6_ADDR_LEN)

#define SET_CTX_ADDRESS4(ctx, addr, port)                                                                              \
    do {                                                                                                               \
        if (ctx->user_family == AF_INET) {                                                                             \
            (ctx)->user_ip4 = (addr)->ip4;                                                                             \
            (ctx)->user_port = port;                                                                                   \
        }                                                                                                              \
    } while (0)

#define SET_CTX_ADDRESS6(ctx, addr, port)                                                                              \
    do {                                                                                                               \
        if (ctx->user_family == AF_INET6) {                                                                            \
            (ctx)->user_ip6[0] = (addr)->ip6[0];                                                                       \
            (ctx)->user_ip6[1] = (addr)->ip6[1];                                                                       \
            (ctx)->user_ip6[2] = (addr)->ip6[2];                                                                       \
            (ctx)->user_ip6[3] = (addr)->ip6[3];                                                                       \
            (ctx)->user_port = port;                                                                                   \
        }                                                                                                              \
    } while (0)
#endif //__BPF_CTX_SOCK_ADDR_H
