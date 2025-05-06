// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include "tc.h"
#include "bpf_log.h"
#include "ipsec_map.h"

// run at pod nic and mark traffic need to encryption.
// It runs on the host side of the eth NIC, as packets
// enter the NIC(i.e., into the host ns network)
SEC("tc_ingress")
int tc_mark_encrypt(struct __sk_buff *ctx)
{
    struct nodeinfo *nodeinfo;
    struct tc_info info = {0};

    if (parser_tc_info(ctx, &info)) {
        return TC_ACT_OK;
    }

    nodeinfo = check_remote_manage_by_kmesh(ctx, &info, info.iph->daddr, info.ip6h->daddr.s6_addr32);
    if (!nodeinfo) {
        return TC_ACT_OK;
    }
    // 0x00e0 mean need encryption in ipsec
    ctx->mark = 0x00e0;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;