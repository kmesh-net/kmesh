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
 */

#ifndef __BPF_CTX_SOCK_ADDR_H
#define __BPF_CTX_SOCK_ADDR_H

typedef struct bpf_sock_addr ctx_buff_t;

// clang-format off
#define KMESH_PORG_CALLS    cgroup/connect4
// clang-format on

#define DECLARE_VAR_ADDRESS(ctx, name)                                                                                 \
    address_t name = {0};                                                                                              \
    name.ipv4 = (ctx)->user_ip4;                                                                                       \
    name.port = (ctx)->user_port;                                                                                      \
    name.protocol =                                                                                                    \
        ((ctx)->protocol == IPPROTO_TCP) ? CORE__SOCKET_ADDRESS__PROTOCOL__TCP : CORE__SOCKET_ADDRESS__PROTOCOL__UDP

#define SET_CTX_ADDRESS(ctx, address)                                                                                  \
    (ctx)->user_ip4 = (address)->ipv4;                                                                                 \
    (ctx)->user_port = (address)->port

#endif //__BPF_CTX_SOCK_ADDR_H
