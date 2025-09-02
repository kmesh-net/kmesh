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
    __u8 protocol = 0;
    bool decrypted = false;
    __u32 mark = 0;

    if (parser_tc_info(ctx, &info)) {
        return TC_ACT_OK;
    }
    if (is_ipv4(&info)) {
        protocol = info.iph->protocol;
    } else if (is_ipv6(&info)) {
        protocol = info.ip6h->nexthdr;
    } else {
        return TC_ACT_OK;
    }

    if (protocol == IPPROTO_ESP) {
        return TC_ACT_OK;
    }

    mark = ctx->mark;
    decrypted = (mark == 0x00d0); // 0x00d0 is same with xfmr state output-mark, which means packet was decrypted and
                                  // then back to ingress

    if (decrypted) {
        return TC_ACT_OK;
    }

    ctx->mark = 0;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;