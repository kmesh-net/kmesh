/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __AUTHZ_H__
#define __AUTHZ_H__

#include "workload_common.h"
#include "bpf_log.h"
#include "xdp.h"
#include "tail_call.h"
#include "workloadapi/security/authorization.pb-c.h"
#include "config.h"

#define AUTH_ALLOW      0
#define AUTH_DENY       1
#define UNMATCHED       0
#define MATCHED         1
#define UNSUPPORTED     2
#define TYPE_SRCIP      (1)
#define TYPE_DSTIP      (1 << 1)
#define CONVERT_FAILED  1
#define CONVERT_SUCCESS 0

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(Istio__Security__Authorization));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_AUTH_POLICY);
} map_of_authz_policy SEC(".maps");

struct match_context {
    __u32 action;
    __u8 policy_index;
    __u8 n_rules;
    wl_policies_v *policies;
    void *rulesPtr;
};

/*
 * This map is used to store the variable that
 * xdp_auth needs to pass during the tail call
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct bpf_sock_tuple));
    __uint(value_size, sizeof(struct match_context));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_AUTH_TAILCALL);
} kmesh_tc_args SEC(".maps");

static inline Istio__Security__Authorization *map_lookup_authz(__u32 policyKey)
{
    return (Istio__Security__Authorization *)kmesh_map_lookup_elem(&map_of_authz_policy, &policyKey);
}

static inline wl_policies_v *get_workload_policies_by_uid(__u32 workload_uid)
{
    return (wl_policies_v *)kmesh_map_lookup_elem(&map_of_wl_policy, &workload_uid);
}

static inline int parser_xdp_info(struct xdp_md *ctx, struct xdp_info *info)
{
    void *begin = (void *)(long)(ctx->data);
    void *end = (void *)(long)(ctx->data_end);

    // eth header
    info->ethh = (struct ethhdr *)begin;
    if ((void *)(info->ethh + 1) > end)
        return PARSER_FAILED;

    // ip4|ip6 header
    begin = info->ethh + 1;
    if ((begin + 1) > end)
        return PARSER_FAILED;
    if (((struct iphdr *)begin)->version == IPv4_VERSION) {
        info->iph = (struct iphdr *)begin;
        if ((void *)(info->iph + 1) > end || (info->iph->protocol != IPPROTO_TCP))
            return PARSER_FAILED;
        begin = (info->iph + 1);
    } else if (((struct iphdr *)begin)->version == IPv6_VERSION) {
        info->ip6h = (struct ipv6hdr *)begin;
        if ((void *)(info->ip6h + 1) > end || (info->ip6h->nexthdr != IPPROTO_TCP))
            return PARSER_FAILED;
        begin = (info->ip6h + 1);
    } else
        return PARSER_FAILED;

    info->tcph = (struct tcphdr *)begin;
    if ((void *)(info->tcph + 1) > end)
        return PARSER_FAILED;
    return PARSER_SUCC;
}

static inline void parser_tuple(struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    if (info->iph->version == IPv4_VERSION) {
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

static int construct_tuple_key(struct xdp_md *ctx, struct bpf_sock_tuple *tuple_info, struct xdp_info *info)
{
    int ret = parser_xdp_info(ctx, info);
    if (ret != PARSER_SUCC) {
        BPF_LOG(ERR, AUTH, "failed to parse xdp_info");
        return PARSER_FAILED;
    }

    parser_tuple(info, tuple_info);

    return PARSER_SUCC;
}

static int match_dst_ports(Istio__Security__Match *match, struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    __u32 *notPorts = NULL;
    __u32 *ports = NULL;
    __u32 i;

    if (match->n_destination_ports == 0 && match->n_not_destination_ports == 0) {
        BPF_LOG(DEBUG, AUTH, "no ports configured, matching by default");
        return MATCHED;
    }

    if (match->n_not_destination_ports != 0) {
        notPorts = KMESH_GET_PTR_VAL(match->not_destination_ports, void *);
        if (!notPorts) {
            BPF_LOG(ERR, AUTH, "failed to retrieve not_destination_ports pointer");
            return UNMATCHED;
        }
#pragma unroll
        for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
            if (i >= match->n_not_destination_ports) {
                break;
            }
            if (info->iph->version == IPv4_VERSION) {
                if (bpf_htons(notPorts[i]) == tuple_info->ipv4.dport) {
                    BPF_LOG(DEBUG, AUTH, "port %u in not_destination_ports, unmatched", notPorts[i]);
                    return UNMATCHED;
                }
            } else {
                if (bpf_htons(notPorts[i]) == tuple_info->ipv6.dport) {
                    BPF_LOG(DEBUG, AUTH, "port %u in not_destination_ports, unmatched", notPorts[i]);
                    return UNMATCHED;
                }
            }
        }
    }
    // if not match not_destination_ports && has no destination_ports, return MATCHED
    if (match->n_destination_ports == 0) {
        BPF_LOG(INFO, AUTH, "no destination_ports configured, matching by default");
        return MATCHED;
    }

    ports = KMESH_GET_PTR_VAL(match->destination_ports, void *);
    if (!ports) {
        BPF_LOG(ERR, AUTH, "failed to retrieve destination_ports pointer");
        return UNMATCHED;
    }
#pragma unroll
    for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
        if (i >= match->n_destination_ports) {
            break;
        }
        if (info->iph->version == IPv4_VERSION) {
            if (bpf_htons(ports[i]) == tuple_info->ipv4.dport) {
                BPF_LOG(INFO, AUTH, "port %u in destination_ports, matched", ports[i]);
                return MATCHED;
            }
        } else {
            if (bpf_htons(ports[i]) == tuple_info->ipv6.dport) {
                BPF_LOG(INFO, AUTH, "port %u in destination_ports, matched", ports[i]);
                return MATCHED;
            }
        }
    }
    BPF_LOG(DEBUG, AUTH, "no matching ports found, unmatched");
    return UNMATCHED;
}

static inline __u32 convert_ipv4_to_u32(const struct ProtobufCBinaryData *ipv4_data)
{
    if (!ipv4_data->data || ipv4_data->len != 4) {
        return 0;
    }

    unsigned char *data = (unsigned char *)KMESH_GET_PTR_VAL(ipv4_data->data, unsigned char);
    if (!data) {
        BPF_LOG(INFO, AUTH, "convert_ipv4_to_u32: Failed to read data from ipv4_data\n");
        return 0;
    }

    return (data[3] << 24) | (data[2] << 16) | (data[1] << 8) | (data[0] << 0);
}

static inline __u32 convert_ipv6_to_u32(struct ip_addr *rule_addr, const struct ProtobufCBinaryData *ipv6_data)
{
    if (!rule_addr || !ipv6_data)
        return CONVERT_FAILED;
    if (!ipv6_data->data || ipv6_data->len != 16) {
        return CONVERT_FAILED;
    }

    unsigned char *v6addr = (unsigned char *)KMESH_GET_PTR_VAL(ipv6_data->data, unsigned char *);
    if (!v6addr) {
        return CONVERT_FAILED;
    }

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            rule_addr->ip6[i] |= (v6addr[i * 4 + j] << (i * 8));
        }
    }

    return CONVERT_SUCCESS;
}

// reference cilium https://github.com/cilium/cilium/blob/main/bpf/lib/ipv6.h#L122
#define GET_PREFIX(PREFIX) bpf_htonl(PREFIX <= 0 ? 0 : PREFIX < 32 ? ((1 << PREFIX) - 1) << (32 - PREFIX) : 0xFFFFFFFF)

static inline void ipv6_addr_clear_suffix(union v6addr *addr, int prefix)
{
    addr->p1 &= GET_PREFIX(prefix);
    prefix -= 32;
    addr->p2 &= GET_PREFIX(prefix);
    prefix -= 32;
    addr->p3 &= GET_PREFIX(prefix);
    prefix -= 32;
    addr->p4 &= GET_PREFIX(prefix);
}

static inline int matchIpv4(__u32 ruleIp, __u32 preFixLen, __be32 targetIP)
{
    __u32 mask = 0;

    if (preFixLen > 32) {
        return UNMATCHED;
    }
    mask = 0xFFFFFFFF << (32 - preFixLen);
    if ((ruleIp & mask) == (targetIP & mask)) {
        return MATCHED;
    }
    return 0;
}

static inline int matchIpv6(struct ip_addr *rule_addr, struct ip_addr *target_addr, __u32 prefixLen)
{
    if (prefixLen > 128)
        return UNMATCHED;

    ipv6_addr_clear_suffix(target_addr, prefixLen);
    if (rule_addr->ip6[0] == target_addr->ip6[0] && rule_addr->ip6[1] == target_addr->ip6[1]
        && rule_addr->ip6[2] == target_addr->ip6[2] && rule_addr->ip6[3] == target_addr->ip6[3]) {
        BPF_LOG(DEBUG, KMESH, "match ipv6\n");
        return MATCHED;
    }

    return UNMATCHED;
}

static inline int
matchIp(struct ProtobufCBinaryData *addrInfo, __u32 preFixLen, struct bpf_sock_tuple *tuple_info, __u8 type)
{
    if (!addrInfo || addrInfo->len == 0) {
        BPF_LOG(ERR, AUTH, "addrInfo is NULL or length is 0\n");
        return UNMATCHED;
    }

    if (addrInfo->len == IPv4_VERSION) {
        __u32 rule_ip = convert_ipv4_to_u32(addrInfo);
        if (type & TYPE_SRCIP) {
            BPF_LOG(
                INFO,
                AUTH,
                "IPv4 match srcip: Rule IP: %x, Prefix Length: %u, Target IP: %x\n",
                rule_ip,
                preFixLen,
                tuple_info->ipv4.saddr);
            return matchIpv4(rule_ip, preFixLen, tuple_info->ipv4.saddr);
        } else if (type & TYPE_DSTIP) {
            BPF_LOG(
                INFO,
                AUTH,
                "IPv4 match dstip: Rule IP: %x, Prefix Length: %u, Target IP: %x\n",
                rule_ip,
                preFixLen,
                tuple_info->ipv4.daddr);
            return matchIpv4(rule_ip, preFixLen, tuple_info->ipv4.daddr);
        } else {
            BPF_LOG(ERR, AUTH, "Unsupported address length: %u\n", addrInfo->len);
        }
    } else if (addrInfo->len == 16) {
        if (type & TYPE_SRCIP) {
            struct ip_addr rule_addr = {0};
            struct ip_addr target_addr = {0};

            int ret = convert_ipv6_to_u32(&rule_addr, addrInfo);
            if (ret != CONVERT_SUCCESS) {
                BPF_LOG(ERR, AUTH, "Failed to convert IPv6 address to u32 format\n");
                return UNMATCHED;
            }

            IP6_COPY(target_addr.ip6, tuple_info->ipv6.saddr);
            return matchIpv6(&rule_addr, &target_addr, preFixLen);
        }
    } else if (type & TYPE_DSTIP) {
        struct ip_addr rule_addr = {0};
        struct ip_addr target_addr = {0};

        int ret = convert_ipv6_to_u32(&rule_addr, addrInfo);
        if (ret != CONVERT_SUCCESS) {
            BPF_LOG(ERR, AUTH, "Failed to convert IPv6 address to u32 format\n");
            return UNMATCHED;
        }

        IP6_COPY(target_addr.ip6, tuple_info->ipv6.daddr);
        return matchIpv6(&rule_addr, &target_addr, preFixLen);
    } else {
        BPF_LOG(ERR, AUTH, "Unsupported address length: %u\n", addrInfo->len);
    }

    return UNMATCHED;
}

static inline int match_dst_ip(Istio__Security__Match *match, struct bpf_sock_tuple *tuple_info)
{
    void *dstPtrs = NULL;
    void *notDstPtrs = NULL;
    void *dstAddr = NULL;
    void *notDstAddr = NULL;
    Istio__Security__Address *dst = NULL;
    Istio__Security__Address *notDst = NULL;
    __u32 i = 0;

    if (match->n_destination_ips == 0 && match->n_not_destination_ips == 0) {
        BPF_LOG(DEBUG, AUTH, "no dstip configured, matching by default");
        return MATCHED;
    }

    // match not_dstIPs
    if (match->n_not_destination_ips != 0) {
        notDstPtrs = KMESH_GET_PTR_VAL(match->not_destination_ips, void *);
        if (!notDstPtrs) {
            BPF_LOG(ERR, AUTH, "failed to retrieve not_dstips pointer\n");
            return UNMATCHED;
        }

#pragma unroll
        for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
            if (i >= match->n_not_destination_ips) {
                break;
            }

            if (bpf_probe_read_kernel(&notDstAddr, sizeof(notDstAddr), &notDstPtrs[i]) != 0) {
                BPF_LOG(ERR, AUTH, "failed to read notSrcAddr address at index %d", i);
                continue;
            }

            notDst = (Istio__Security__Address *)KMESH_GET_PTR_VAL((void *)notDstAddr, Istio__Security__Address);
            if (!notDst) {
                continue;
            }
            if (matchIp(&notDst->address, notDst->length, tuple_info, TYPE_DSTIP) == MATCHED) {
                return UNMATCHED;
            }
        }
    }

    if (match->n_destination_ips != 0) {
        dstPtrs = KMESH_GET_PTR_VAL(match->destination_ips, void *);
        if (!dstPtrs) {
            BPF_LOG(ERR, AUTH, "failed to get dstips ptr\n");
            return UNMATCHED;
        }

#pragma unroll
        for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
            if (i >= match->n_destination_ips) {
                break;
            }

            if (bpf_probe_read_kernel(&dstAddr, sizeof(dstAddr), &dstPtrs[i]) != 0) {
                BPF_LOG(ERR, AUTH, "failed to read dst address at index %d", i);
                continue;
            }

            dst = (Istio__Security__Address *)KMESH_GET_PTR_VAL((void *)dstAddr, Istio__Security__Address);
            if (!dst) {
                continue;
            }
            if (matchIp(&dst->address, dst->length, tuple_info, TYPE_DSTIP) == MATCHED) {
                return MATCHED;
            }
        }
    }
    BPF_LOG(DEBUG, AUTH, "no matching dstip found, unmatched");
    return UNMATCHED;
}

static inline int match_src_ip(Istio__Security__Match *match, struct bpf_sock_tuple *tuple_info)
{
    void *srcPtrs = NULL;
    void *notSrcPtrs = NULL;
    void *srcAddr = NULL;
    void *notSrcAddr = NULL;
    Istio__Security__Address *src = NULL;
    Istio__Security__Address *notSrc = NULL;
    __u32 i = 0;

    if (match->n_source_ips == 0 && match->n_not_source_ips == 0) {
        BPF_LOG(DEBUG, AUTH, "no srcip configured, matching by default");
        return MATCHED;
    }

    // match not_srcIPs
    if (match->n_not_source_ips != 0) {
        notSrcPtrs = KMESH_GET_PTR_VAL(match->not_source_ips, void *);
        if (!notSrcPtrs) {
            BPF_LOG(ERR, AUTH, "failed to retrieve not_srcips pointer\n");
            return UNMATCHED;
        }

#pragma unroll
        for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
            if (i >= match->n_not_source_ips) {
                break;
            }

            if (bpf_probe_read_kernel(&notSrcAddr, sizeof(notSrcAddr), &notSrcPtrs[i]) != 0) {
                BPF_LOG(ERR, AUTH, "failed to read notSrcAddr address at index %d", i);
                continue;
            }

            notSrc = (Istio__Security__Address *)KMESH_GET_PTR_VAL((void *)notSrcAddr, Istio__Security__Address);
            if (!notSrc) {
                continue;
            }
            if (matchIp(&notSrc->address, notSrc->length, tuple_info, TYPE_SRCIP) == MATCHED) {
                return UNMATCHED;
            }
        }
    }

    if (match->n_source_ips != 0) {
        srcPtrs = KMESH_GET_PTR_VAL(match->source_ips, void *);
        if (!srcPtrs) {
            BPF_LOG(ERR, AUTH, "failed to get srcips ptr\n");
            return UNMATCHED;
        }

#pragma unroll
        for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
            if (i >= match->n_source_ips) {
                break;
            }

            if (bpf_probe_read_kernel(&srcAddr, sizeof(srcAddr), &srcPtrs[i]) != 0) {
                BPF_LOG(ERR, AUTH, "failed to read src address at index %d", i);
                continue;
            }

            src = (Istio__Security__Address *)KMESH_GET_PTR_VAL((void *)srcAddr, Istio__Security__Address);
            if (!src) {
                continue;
            }
            if (matchIp(&src->address, src->length, tuple_info, TYPE_SRCIP) == MATCHED) {
                return MATCHED;
            }
        }
    }
    BPF_LOG(DEBUG, AUTH, "no matching srcip found, unmatched");
    return UNMATCHED;
}

static inline int match_IPs(Istio__Security__Match *match, struct bpf_sock_tuple *tuple_info)
{
    return match_src_ip(match, tuple_info) || match_dst_ip(match, tuple_info);
}

static int match_check(Istio__Security__Match *match, struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    __u32 matchResult;

    // if multiple types are set, they are AND-ed, all matched is a match
    // todo: add other match types
    matchResult = match_dst_ports(match, info, tuple_info) && match_IPs(match, tuple_info);
    return matchResult;
}

static int clause_match_check(Istio__Security__Clause *cl, struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    void *matchsPtr = NULL;
    Istio__Security__Match *match = NULL;
    __u32 i;

    if (cl->n_matches == 0) {
        return UNMATCHED;
    }
    matchsPtr = KMESH_GET_PTR_VAL(cl->matches, void *);
    if (!matchsPtr) {
        return MATCHED;
    }

#pragma unroll
    for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
        if (i >= cl->n_matches) {
            break;
        }
        match = (Istio__Security__Match *)KMESH_GET_PTR_VAL((void *)*((__u64 *)matchsPtr + i), Istio__Security__Match);
        if (!match) {
            continue;
        }
        // if any match matches, it is a match
        if (match_check(match, info, tuple_info) == MATCHED) {
            return MATCHED;
        }
    }
    return UNMATCHED;
}

static int rule_match_check(Istio__Security__Rule *rule, struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    void *clausesPtr = NULL;
    Istio__Security__Clause *clause = NULL;
    __u32 i;

    if (rule->n_clauses == 0) {
        return MATCHED;
    }
    // Clauses are AND-ed.
    clausesPtr = KMESH_GET_PTR_VAL(rule->clauses, void *);
    if (!clausesPtr) {
        BPF_LOG(ERR, AUTH, "failed to get clauses from rule\n");
        return UNMATCHED;
    }

    for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
        if (i >= rule->n_clauses) {
            break;
        }
        clause =
            (Istio__Security__Clause *)KMESH_GET_PTR_VAL((void *)*((__u64 *)clausesPtr + i), Istio__Security__Clause);
        if (!clause) {
            continue;
        }
        if (clause_match_check(clause, info, tuple_info) == UNMATCHED) {
            return UNMATCHED;
        }
    }
    return MATCHED;
}

SEC("xdp_auth")
int policy_check(struct xdp_md *ctx)
{
    struct match_context *match_ctx;
    wl_policies_v *policies;
    void *rulesPtr;
    __u32 policyId;
    Istio__Security__Authorization *policy;
    struct bpf_sock_tuple tuple_key = {0};
    struct xdp_info info = {0};
    int ret;

    if (construct_tuple_key(ctx, &tuple_key, &info) != PARSER_SUCC) {
        BPF_LOG(ERR, AUTH, "policy_check, Failed to get tuple key");
        return XDP_PASS;
    }

    match_ctx = bpf_map_lookup_elem(&kmesh_tc_args, &tuple_key);
    if (!match_ctx) {
        BPF_LOG(ERR, AUTH, "failed to retrieve tailcall context from kmesh_tc_args");
        return XDP_PASS;
    }

    policies = match_ctx->policies;
    if (!policies) {
        return XDP_PASS;
    }

    // Safely access policyId and check if the policy exists
    if (bpf_probe_read_kernel(&policyId, sizeof(policyId), (void *)(policies->policyIds + match_ctx->policy_index))
        != 0) {
        BPF_LOG(ERR, AUTH, "failed to read policyId, throw it to user auth");
        goto auth_in_user_space;
    }
    policy = map_lookup_authz(policyId);
    if (!policy) {
        // if no policy matches in xdp, throw it to user auth
        BPF_LOG(INFO, AUTH, "no more policy, throw it to user auth");
        goto auth_in_user_space;
    } else {
        rulesPtr = KMESH_GET_PTR_VAL(policy->rules, void *);
        if (!rulesPtr) {
            BPF_LOG(ERR, AUTH, "failed to get rules from policies\n");
            return XDP_PASS;
        }
        match_ctx->rulesPtr = rulesPtr;
        match_ctx->n_rules = policy->n_rules;
        match_ctx->action = policy->action;
        ret = bpf_map_update_elem(&kmesh_tc_args, &tuple_key, match_ctx, BPF_ANY);
        if (ret < 0) {
            BPF_LOG(ERR, AUTH, "failed to update map, error: %d", ret);
            return XDP_PASS;
        }
        bpf_tail_call(ctx, &map_of_xdp_tailcall, TAIL_CALL_RULE_CHECK);
    }
    return XDP_PASS;

auth_in_user_space:
    if (bpf_map_delete_elem(&kmesh_tc_args, &tuple_key) != 0) {
        BPF_LOG(DEBUG, AUTH, "failed to delete context from map");
    }
    bpf_tail_call(ctx, &map_of_xdp_tailcall, TAIL_CALL_AUTH_IN_USER_SPACE);
    return XDP_PASS;
}

SEC("xdp_auth")
int rule_check(struct xdp_md *ctx)
{
    struct match_context *match_ctx;
    struct bpf_sock_tuple tuple_key = {0};
    struct xdp_info info = {0};
    void *rulesPtr;
    __u64 rule_addr;
    void *rule;
    int ret;
    int i;

    if (construct_tuple_key(ctx, &tuple_key, &info) != PARSER_SUCC) {
        BPF_LOG(ERR, AUTH, "failed to get tuple key in rule_check");
        return XDP_PASS;
    }

    match_ctx = bpf_map_lookup_elem(&kmesh_tc_args, &tuple_key);
    if (!match_ctx) {
        BPF_LOG(ERR, AUTH, "failed to retrieve match_context from map");
        return XDP_PASS;
    }
    for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
        if (i >= match_ctx->n_rules) {
            BPF_LOG(DEBUG, AUTH, "rule index %d exceeds rule count %d, exiting loop", i, match_ctx->n_rules);
            break;
        }
        if (!match_ctx) {
            BPF_LOG(ERR, AUTH, "failed to retrieve match_ctx from map");
            return XDP_PASS;
        }
        rulesPtr = match_ctx->rulesPtr;
        if (!rulesPtr) {
            BPF_LOG(ERR, AUTH, "rulesPtr is null");
            return XDP_PASS;
        }
        if (bpf_probe_read_kernel(&rule_addr, sizeof(rule_addr), &rulesPtr[i]) != 0) {
            BPF_LOG(ERR, AUTH, "failed to read rule address at index %d", i);
            continue;
        }

        rule = (Istio__Security__Rule *)KMESH_GET_PTR_VAL((void *)rule_addr, Istio__Security__Rule);
        if (!rule) {
            continue;
        }
        if (rule_match_check(rule, &info, &tuple_key) == MATCHED) {
            BPF_LOG(
                INFO,
                AUTH,
                "rule matched, action: %s",
                match_ctx->action == ISTIO__SECURITY__ACTION__DENY ? "DENY" : "ALLOW");
            if (bpf_map_delete_elem(&kmesh_tc_args, &tuple_key) != 0) {
                BPF_LOG(INFO, AUTH, "failed to delete tail call context from map");
            }
            __u32 auth_result = match_ctx->action == ISTIO__SECURITY__ACTION__DENY ? AUTH_DENY : AUTH_ALLOW;
            if (bpf_map_update_elem(&map_of_auth_result, &tuple_key, &auth_result, BPF_ANY) != 0) {
                BPF_LOG(ERR, AUTH, "failed to update auth result in map_of_auth_result");
            }
            return match_ctx->action == ISTIO__SECURITY__ACTION__DENY ? XDP_DROP : XDP_PASS;
        }
    }

    match_ctx->policy_index++;
    if (match_ctx->policy_index >= MAX_MEMBER_NUM_PER_POLICY) {
        BPF_LOG(ERR, AUTH, "policy index out of bounds");
        bpf_tail_call(ctx, &map_of_xdp_tailcall, TAIL_CALL_AUTH_IN_USER_SPACE);
    }

    ret = bpf_map_update_elem(&kmesh_tc_args, &tuple_key, match_ctx, BPF_ANY);
    if (ret < 0) {
        BPF_LOG(ERR, AUTH, "failed to update map, error: %d", ret);
        return XDP_PASS;
    }
    bpf_tail_call(ctx, &map_of_xdp_tailcall, TAIL_CALL_POLICY_CHECK);
    return XDP_PASS;
}

#endif