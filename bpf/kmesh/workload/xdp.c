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
#include "authz.h"
#include "xdp.h"

static inline void shutdown_tuple(struct xdp_info *info)
{
    info->tcph->fin = 0;
    info->tcph->syn = 0;
    info->tcph->rst = 1;
    info->tcph->psh = 0;
    info->tcph->ack = 0;
}

static inline int should_shutdown(struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    __u32 *value = bpf_map_lookup_elem(&map_of_auth, tuple_info);
    if (value && *value == 1) {
        if (info->iph->version == 4)
            BPF_LOG(
                INFO,
                XDP,
                "auth denied, src ip: %s, port: %u\n",
                ip2str(&tuple_info->ipv4.saddr, true),
                bpf_ntohs(tuple_info->ipv4.sport));
        else
            BPF_LOG(
                INFO,
                XDP,
                "auth denied, src ip: %s, port: %u\n",
                ip2str(&tuple_info->ipv6.saddr[0], false),
                bpf_ntohs(tuple_info->ipv6.sport));
        bpf_map_delete_elem(&map_of_auth, tuple_info);
        return AUTH_FORBID;
    }
    return AUTH_PASS;
}

static inline int xdp_deny_packet(struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    if (info->iph != NULL && info->iph->version == 4) {
        BPF_LOG(
            INFO,
            XDP,
            "auth denied, src ip: %s, dst ip %s, dst port: %u\n",
            ip2str(&tuple_info->ipv4.saddr, true),
            ip2str(&tuple_info->ipv4.daddr, true),
            bpf_ntohs(tuple_info->ipv4.dport));
    } else {
        BPF_LOG(
            INFO,
            XDP,
            "auth denied, src ip: %s, dst ip %s, dst port: %u\n",
            ip2str(&tuple_info->ipv6.saddr[0], false),
            ip2str(&tuple_info->ipv6.daddr[0], false),
            bpf_ntohs(tuple_info->ipv6.dport));
    }
    return XDP_DROP;
}

static bool is_authz_offload_enabled()
{
    int kmesh_config_key = 0;
    struct kmesh_config *value = {0};
    value = kmesh_map_lookup_elem(&kmesh_config_map, &kmesh_config_key);
    if (!value)
        return false;
    return ((*value).authz_offload == 1);
}

static inline wl_policies_v *get_workload_policies(struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    frontend_key frontend_k = {};
    frontend_value *frontend_v = NULL;
    __u32 workload_uid = 0;

    if (info->iph->version == 4) {
        frontend_k.addr.ip4 = tuple_info->ipv4.daddr;
    } else if (is_ipv4_mapped_addr(tuple_info->ipv6.daddr)) {
        frontend_k.addr.ip4 = tuple_info->ipv6.daddr[3];
    } else {
        bpf_memcpy(frontend_k.addr.ip6, tuple_info->ipv6.daddr, IPV6_ADDR_LEN);
    }
    frontend_v = kmesh_map_lookup_elem(&map_of_frontend, &frontend_k);
    if (!frontend_v) {
        BPF_LOG(INFO, XDP, "failed to get frontend in xdp");
        return AUTH_ALLOW;
    }
    workload_uid = frontend_v->upstream_id;
    return get_workload_policies_by_uid(workload_uid);
}

SEC("xdp_auth")
int xdp_authz(struct xdp_md *ctx)
{
    if (!is_authz_offload_enabled()) {
        bpf_tail_call(ctx, &xdp_tailcall_map, TAIL_CALL_AUTH_IN_USER_SPACE);
        return XDP_PASS;
    }

    struct match_context match_ctx = {0};
    struct bpf_sock_tuple tuple_key = {0};
    struct xdp_info info = {0};
    wl_policies_v *policies = NULL;
    int ret;

    if (parser_xdp_info(ctx, &info) == PARSER_FAILED)
        return XDP_PASS;
    if (info.iph->version != 4 && info.iph->version != 6)
        return XDP_PASS;

    // never failed
    parser_tuple(&info, &tuple_key);
    int *value = bpf_map_lookup_elem(&map_of_auth, &tuple_key);
    if (!value) {
        policies = get_workload_policies(&info, &tuple_key);
        if (!policies) {
            return XDP_PASS;
        }
        match_ctx.policies = policies;
        match_ctx.policy_index = 0;
        ret = bpf_map_update_elem(&kmesh_tc_args, &tuple_key, &match_ctx, BPF_ANY);
        if (ret < 0) {
            BPF_LOG(ERR, AUTH, "Failed to update map, error: %d", ret);
            return XDP_PASS;
        }

        bpf_tail_call(ctx, &xdp_tailcall_map, TAIL_CALL_POLICY_CHECK);
        return XDP_PASS;
    } else {
        return *value ? XDP_DROP : XDP_PASS;
    }
}

SEC("xdp_auth")
int xdp_shutdown_in_userspace(struct xdp_md *ctx)
{
    struct xdp_info info = {0};
    struct bpf_sock_tuple tuple_info = {0};

    if (parser_xdp_info(ctx, &info) == PARSER_FAILED)
        return XDP_PASS;
    if (info.iph->version != 4 && info.iph->version != 6)
        return XDP_PASS;

    // never failed
    parser_tuple(&info, &tuple_info);

    if (should_shutdown(&info, &tuple_info) == AUTH_FORBID)
        shutdown_tuple(&info);

    // If auth denied, it still returns XDP_PASS here, so next time when a client package is
    // sent to server, it will be shutdown since server's RST has been set
    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;