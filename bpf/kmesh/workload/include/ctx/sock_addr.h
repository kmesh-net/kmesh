/*
 * Copyright 2024 The Kmesh Authors.
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

 * Author: kwb0523
 * Create: 2024-01-20
 */

#ifndef __BPF_CTX_SOCK_ADDR_H
#define __BPF_CTX_SOCK_ADDR_H

#include "common.h"
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
            bpf_memcpy((ctx)->user_ip6, (addr)->ip6, IPV6_ADDR_LEN);                                                   \
            (ctx)->user_port = port;                                                                                   \
        }                                                                                                              \
    } while (0)

#endif //__BPF_CTX_SOCK_ADDR_H
