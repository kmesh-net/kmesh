// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include "tc.h"
#include "bpf_log.h"
#include "ipsec_map.h"

// run at pod nic and mark traffic need to encryption
SEC("tc_ingress")
int tc_mark_encrypt(struct __sk_buff *ctx)
{
    struct nodeinfo *nodeinfo;

    struct tc_info info = {0};

    if (parser_tc_info(ctx, &info)) {
        return TC_ACT_OK;
    }

    nodeinfo = getNodeInfo(ctx, &info, info.iph->daddr, info.ip6h->daddr.s6_addr32);
    if (!nodeinfo) {
        return TC_ACT_OK;
    }
    ctx->mark = ((nodeinfo->nodeid) << 16) + ((nodeinfo->spi) << 8) + 0x00e0;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;