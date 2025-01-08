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
    struct nodeinfo *nodeinfo;
    struct tc_info info = {0};

    if (parser_tc_info(ctx, &info)) {
        return TC_ACT_OK;
    }
    nodeinfo = check_remote_manage_by_kmesh(ctx, &info, info.iph->saddr, info.ip6h->saddr.s6_addr32);
    if (!nodeinfo) {
        return TC_ACT_OK;
    }
    // 0x00d0 mean need decryption in ipsec
    ctx->mark = 0x00d0;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;