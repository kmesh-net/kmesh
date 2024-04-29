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
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include "config.h"
#include "bpf_log.h"
#include "workload.h"

#define AUTH_PASS   0
#define AUTH_FORBID 1

#define PARSER_FAILED 1
#define PARSER_SUCC   0

struct xdp_info {
    struct ethhdr *ethh;
    struct iphdr *iph;
    struct tcphdr *tcph;
};

static inline int get_hdr_ptr(struct xdp_md *ctx, struct ethhdr **ethh, struct iphdr **iph, struct tcphdr **tcph)
{
    void *begin = (void *)(ctx->data);
    void *end = (void *)(ctx->data_end);

    *ethh = (struct ethhdr *)begin;
    if ((void *)((*ethh) + 1) > end)
        return PARSER_FAILED;
    if ((*ethh)->h_proto != bpf_htons(ETH_P_IP))
        return PARSER_FAILED;

    *iph = (struct iphdr *)(*ethh + 1);
    if ((void *)((*iph) + 1) > end)
        return PARSER_FAILED;
    if ((*iph)->protocol != IPPROTO_TCP)
        return PARSER_FAILED;

    *tcph = (struct tcphdr *)(*iph + 1);
    if ((void *)((*tcph) + 1) > end)
        return PARSER_FAILED;

    return PARSER_SUCC;
}

static inline void parser_tuple(struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    tuple_info->ipv4.saddr = info->iph->saddr;
    tuple_info->ipv4.daddr = info->iph->daddr;
    tuple_info->ipv4.sport = info->tcph->source;
    tuple_info->ipv4.dport = info->tcph->dest;
}

static inline void shutdown_tuple(struct xdp_info *info)
{
    info->tcph->fin = 0;
    info->tcph->syn = 0;
    info->tcph->rst = 1;
    info->tcph->psh = 0;
    info->tcph->ack = 0;
}

static inline int should_shutdown(struct bpf_sock_tuple *tuple_info)
{
    __u32 *value = bpf_map_lookup_elem(&map_of_auth, tuple_info);
    if (value) {
        BPF_LOG(
            INFO,
            XDP,
            "auth denied, src ip: %u, port: %u\n",
            bpf_ntohl(tuple_info->ipv4.saddr),
            bpf_ntohs(tuple_info->ipv4.sport));
        bpf_map_delete_elem(&map_of_auth, tuple_info);
        return AUTH_FORBID;
    }
    return AUTH_PASS;
}

static inline int parser_xdp_info(struct xdp_md *ctx, struct xdp_info *info)
{
    return get_hdr_ptr(ctx, &info->ethh, &info->iph, &info->tcph);
}

SEC("xdp_auth")
int xdp_shutdown(struct xdp_md *ctx)
{
    struct xdp_info info = {0};
    struct bpf_sock_tuple tuple_info = {0};

    if (parser_xdp_info(ctx, &info) == PARSER_FAILED)
        return XDP_PASS;

    // never failed
    parser_tuple(&info, &tuple_info);
    if (should_shutdown(&tuple_info) == AUTH_FORBID)
        shutdown_tuple(&info);

    // If auth denied, it still returns XDP_PASS here, so next time when a client package is
    // sent to server, it will be shutdown since server's RST has been set
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;