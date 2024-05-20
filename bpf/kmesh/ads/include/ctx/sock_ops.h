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

 * Author: supercharge-xsy
 * Create: 2023-9-20
 */

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
