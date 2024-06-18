// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include "config.h"
#include "bpf_log.h"
#include "workload.h"
#include "bpf_common.h"

#define PARSER_FAILED 1
#define PARSER_SUCC   0

struct xdp_info {
    struct ethhdr *ethh;
    union {
        struct iphdr *iph;
        struct ipv6hdr *ip6h;
    };
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
    if (info->iph->version == 4) {
        tuple_info->ipv4.saddr = info->iph->saddr;
        tuple_info->ipv4.daddr = info->iph->daddr;
        tuple_info->ipv4.sport = info->tcph->source;
        tuple_info->ipv4.dport = info->tcph->dest;
    } else {
        bpf_memcpy((__u8 *)tuple_info->ipv6.saddr, info->ip6h->saddr.in6_u.u6_addr8, IPV6_ADDR_LEN);
        bpf_memcpy((__u8 *)tuple_info->ipv6.daddr, info->ip6h->daddr.in6_u.u6_addr8, IPV6_ADDR_LEN);
        tuple_info->ipv6.sport = info->tcph->source;
        tuple_info->ipv6.dport = info->tcph->dest;
    }
}

static inline void shutdown_tuple(struct xdp_info *info)
{
    info->tcph->fin = 0;
    info->tcph->syn = 0;
    info->tcph->rst = 1;
    info->tcph->psh = 0;
    info->tcph->ack = 0;
}

static inline int check_auth(struct bpf_sock_tuple *tuple_info)
{
    __u32 *value = bpf_map_lookup_elem(&map_of_auth, tuple_info);
    if (value) {
        BPF_LOG(
            INFO,
            XDP,
            "auth denied(%u), src ip: %pI4h, port: %u\n",
            *value,
            &tuple_info->ipv4.saddr,
            bpf_ntohs(tuple_info->ipv4.sport));   
        return *value;
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
    int ret = 0;
    struct xdp_info info = {0};
    struct bpf_sock_tuple tuple_info = {0};

    if (parser_xdp_info(ctx, &info) == PARSER_FAILED)
        return XDP_PASS;

    if (info.iph->version != 4 && info.iph->version != 6)
        return XDP_PASS;

    // never failed
    parser_tuple(&info, &tuple_info);
    ret = check_auth(&tuple_info);
    if (ret == AUTH_PROCESSING)
        return XDP_DROP;

    if (ret == AUTH_FORBID) {
        shutdown_tuple(&info);
        bpf_map_delete_elem(&map_of_auth, &tuple_info);
    }
    // If auth denied, it still returns XDP_PASS here, so next time when a client package is
    // sent to server, it will be shutdown since server's RST has been set
    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;