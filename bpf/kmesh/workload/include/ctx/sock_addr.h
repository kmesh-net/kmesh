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

typedef enum {
    PROTOCOL_TCP = 0,
    PROTOCOL_UDP,
} protocol_t;

#define IPV6_ADDR_LEN 16
typedef struct bpf_sock_addr ctx_buff_t;

#define DECLARE_FRONTEND_KEY(ctx, key)                                                                                 \
    frontend_key key = {0};                                                                                            \
    if (ctx->user_family == AF_INET)                                                                                   \
        key.ipv4 = (ctx)->user_ip4;                                                                                    \
    else if (ctx->user_family == AF_INET6)                                                                             \
    bpf_memcpy(key.ipv6, (ctx)->user_ip6, IPV6_ADDR_LEN)

#define SET_CTX_ADDRESS(ctx, address)                                                                                  \
    if (ctx->user_family == AF_INET)                                                                                   \
        (ctx)->user_ip4 = (address).ipv4;                                                                              \
    else                                                                                                               \
        bpf_memcpy((ctx)->user_ip6, (address).ipv6, IPV6_ADDR_LEN);                                                    \
    (ctx)->user_port = (address).port

#endif //__BPF_CTX_SOCK_ADDR_H
