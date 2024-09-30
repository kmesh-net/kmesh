/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __XDP_H__
#define __XDP_H__

#define AUTH_PASS   0
#define AUTH_FORBID 1

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

#endif
