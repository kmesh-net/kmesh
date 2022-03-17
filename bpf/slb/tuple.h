/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2021-09-17
 */

#ifndef _TUPLE_H_
#define _TUPLE_H_

#include "common.h"
#include <linux/ip.h>
#include <linux/tcp.h>

#define TUPLE_FLAGS_INGRESS 0
#define TUPLE_FLAGS_EGRESS 1
#define PIN_GLOBAL_NS		2

typedef struct {
    __u32 protocol;
    __u32 src_ipv4;
    __u32 src_ipv6[4];
    __u32 src_port;
    __u32 dst_ipv4;
    __u32 dst_ipv6[4];
    __u32 dst_port;
    /* marked nat or rev-nat */
    __u32 flags;
} tuple_t;


#define DECLARE_TUPLE(src, dst, tuple) \
    tuple_t tuple = {0}; \
    (tuple).src_ipv4 = (src)->ipv4; \
    (tuple).src_port = (src)->port; \
    (tuple).protocol = (src)->protocol; \
    (tuple).dst_ipv4 = (dst)->ipv4; \
    (tuple).dst_port = (dst)->port;

static inline
void parse_tuple(struct iphdr* iph, struct tcphdr* tcph, tuple_t* tuple)
{
    tuple->dst_ipv4= iph->daddr;
    tuple->dst_port = tcph->dest;
    tuple->protocol = iph->protocol;
    tuple->src_ipv4 = iph->saddr;
    tuple->src_port = tcph->source;
    return;
}


#endif // _TUPLE_H_