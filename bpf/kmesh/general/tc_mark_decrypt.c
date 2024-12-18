// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include "tc.h"
#include "bpf_log.h"
#include "common.h"
#include "ipsec_map.h"

// run at node nic and mark traffic need to decryption
SEC("tc_ingress")
int tc_mark_decrypt(struct __sk_buff *ctx)
{
    __u16 nodeid;
    struct nodeinfo *nodeinfo;
    struct tc_info info = {0};

    if (parser_tc_info(ctx, &info)) {
        return TC_ACT_OK;
    }
    nodeinfo = getNodeInfo(ctx, &info, info.iph->saddr, info.ip6h->saddr.s6_addr32);
    if (!nodeinfo) {
        return TC_ACT_OK;
    }
    nodeid = nodeinfo->nodeid;
    ctx->mark = (nodeid << 16) + 0x00d0;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;