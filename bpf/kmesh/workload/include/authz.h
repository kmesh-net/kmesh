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
    char *policy_name;
    __u8 policy_index;
    bool need_tailcall_to_userspace;
    __u8 n_rules;
    int auth_result;
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

/**
 * Struct for IP matching parameters.
 */
struct MatchIpParams {
    struct bpf_sock_tuple *tuple_info;
    // Pointer to the list of allowed IP addresses.
    void *ip_list;
    // Pointer to the list of denied IP addresses.
    void *not_ip_list;
    // Number of allowed/denyed IP addresses.
    __u32 n_ips;
    // Number of not allow/denyed IP addresses.
    __u32 n_not_ips;
    // Type of IP addresses (srcIP/dstIp).
    int ip_type;
};

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
    if (((struct iphdr *)begin)->version == IPV4_VERSION) {
        info->iph = (struct iphdr *)begin;
        if ((void *)(info->iph + 1) > end || (info->iph->protocol != IPPROTO_TCP))
            return PARSER_FAILED;
        begin = (info->iph + 1);
    } else if (((struct iphdr *)begin)->version == IPV6_VERSION) {
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
    if (info->iph->version == IPV4_VERSION) {
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
            if (info->iph->version == IPV4_VERSION) {
                if (bpf_htons(notPorts[i]) == tuple_info->ipv4.dport) {
                    return UNMATCHED;
                }
            } else {
                if (bpf_htons(notPorts[i]) == tuple_info->ipv6.dport) {
                    return UNMATCHED;
                }
            }
        }
    }
    // if not match not_destination_ports && has no destination_ports, return MATCHED
    if (match->n_destination_ports == 0) {
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
        if (info->iph->version == IPV4_VERSION) {
            if (bpf_htons(ports[i]) == tuple_info->ipv4.dport) {
                return MATCHED;
            }
        } else {
            if (bpf_htons(ports[i]) == tuple_info->ipv6.dport) {
                return MATCHED;
            }
        }
    }
    return UNMATCHED;
}

/* This function is used to convert the IP address
 * from big-endian storage to u32 type data.
 */
static inline __u32 convert_ipv4_to_u32(const struct ProtobufCBinaryData *ipv4_data, bool is_ipv4_in_ipv6)
{
    if (!ipv4_data->data || (ipv4_data->len != 4 && ipv4_data->len != 16)) {
        return 0;
    }

    unsigned char *data = (unsigned char *)KMESH_GET_PTR_VAL(ipv4_data->data, unsigned char);
    if (!data) {
        BPF_LOG(ERR, AUTH, "failed to read raw ipv4 data\n");
        return 0;
    }

    if (is_ipv4_in_ipv6) {
        __u32 ipv4_addr = 0;
        ipv4_addr = (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | (data[15]);
        return ipv4_addr;
    }

    return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | (data[3]);
}

static inline __u32 convert_ipv6_to_ip6addr(struct ip_addr *rule_addr, const struct ProtobufCBinaryData *ipv6_data)
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

static inline void ipv6_addr_clear_suffix(__u32 ip6[4], int prefix)
{
    ip6[0] &= GET_PREFIX(prefix);
    prefix -= 32;
    ip6[1] &= GET_PREFIX(prefix);
    prefix -= 32;
    ip6[2] &= GET_PREFIX(prefix);
    prefix -= 32;
    ip6[3] &= GET_PREFIX(prefix);
}

static inline int match_ipv4_rule(__u32 ruleIp, __u32 preFixLen, struct bpf_sock_tuple *tuple_info, __u8 type)
{
    __u32 mask = 0;
    __be32 targetIP = (type & TYPE_SRCIP) ? tuple_info->ipv4.saddr : tuple_info->ipv4.daddr;

    if (preFixLen > 32) {
        return UNMATCHED;
    }
    mask = 0xFFFFFFFF << (32 - preFixLen);
    if ((ruleIp & mask) == (bpf_ntohl(targetIP) & mask)) {
        return MATCHED;
    }

    return UNMATCHED;
}

static inline int match_ipv6_rule(struct ip_addr *rule_addr, struct ip_addr *target_addr, __u32 prefixLen)
{
    if (prefixLen > 128)
        return UNMATCHED;

    ipv6_addr_clear_suffix(target_addr->ip6, prefixLen);
    if (rule_addr->ip6[0] == target_addr->ip6[0] && rule_addr->ip6[1] == target_addr->ip6[1]
        && rule_addr->ip6[2] == target_addr->ip6[2] && rule_addr->ip6[3] == target_addr->ip6[3]) {
        return MATCHED;
    }

    return UNMATCHED;
}

static inline int
match_ip_rule(struct ProtobufCBinaryData *addrInfo, __u32 preFixLen, struct bpf_sock_tuple *tuple_info, __u8 type)
{
    if (!addrInfo || addrInfo->len == 0) {
        return UNMATCHED;
    }

    if (addrInfo->len == IPV4_BYTE_LEN) {
        __u32 rule_ip = convert_ipv4_to_u32(addrInfo, false);
        return match_ipv4_rule(rule_ip, preFixLen, tuple_info, type);
    } else if (addrInfo->len == IPV6_BYTE_LEN) {
        struct ip_addr rule_addr = {0};
        struct ip_addr target_addr = {0};

        if (type & (TYPE_SRCIP | TYPE_DSTIP)) {
            int ret = convert_ipv6_to_ip6addr(&rule_addr, addrInfo);
            if (ret != CONVERT_SUCCESS) {
                return UNMATCHED;
            }
            if (is_ipv4_mapped_addr(rule_addr.ip6)) {
                __u32 rule_ip = convert_ipv4_to_u32(addrInfo, true);
                return match_ipv4_rule(rule_ip, preFixLen, tuple_info, type);
            } else {
                if (type & TYPE_SRCIP) {
                    IP6_COPY(target_addr.ip6, tuple_info->ipv6.saddr);
                } else if (type & TYPE_DSTIP) {
                    IP6_COPY(target_addr.ip6, tuple_info->ipv6.daddr);
                }
            }
            return match_ipv6_rule(&rule_addr, &target_addr, preFixLen);
        }
    }
    return UNMATCHED;
}

static inline int match_ip_common(struct MatchIpParams *params)
{
    void *ipPtrs = NULL;
    void *notIpPtrs = NULL;
    void *ipAddr = NULL;
    void *notIpAddr = NULL;
    Istio__Security__Address *ip = NULL;
    Istio__Security__Address *notIp = NULL;
    __u32 i = 0;

    if (!params || !params->tuple_info) {
        return UNMATCHED;
    }

    if (params->n_ips == 0 && params->n_not_ips == 0) {
        return MATCHED;
    }

    // Match `not_` IPs
    if (params->n_not_ips != 0) {
        notIpPtrs = KMESH_GET_PTR_VAL(params->not_ip_list, void *);
        if (!notIpPtrs) {
            return UNMATCHED;
        }

#pragma unroll
        for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
            if (i >= params->n_not_ips) {
                break;
            }

            if (bpf_probe_read_kernel(&notIpAddr, sizeof(notIpAddr), &notIpPtrs[i]) != 0) {
                continue;
            }

            if (!notIpAddr) {
                continue;
            }

            notIp = (Istio__Security__Address *)KMESH_GET_PTR_VAL((void *)notIpAddr, Istio__Security__Address);
            if (!notIp) {
                continue;
            }

            if (match_ip_rule(&notIp->address, notIp->length, params->tuple_info, params->ip_type) == MATCHED) {
                return UNMATCHED;
            }
        }
    }

    // Match IPs
    if (params->n_ips != 0) {
        ipPtrs = KMESH_GET_PTR_VAL(params->ip_list, void *);
        if (!ipPtrs) {
            return UNMATCHED;
        }

#pragma unroll
        for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
            if (i >= params->n_ips) {
                break;
            }

            if (bpf_probe_read_kernel(&ipAddr, sizeof(ipAddr), &ipPtrs[i]) != 0) {
                continue;
            }

            if (!ipAddr) {
                continue;
            }

            ip = (Istio__Security__Address *)KMESH_GET_PTR_VAL((void *)ipAddr, Istio__Security__Address);
            if (!ip) {
                continue;
            }

            if (match_ip_rule(&ip->address, ip->length, params->tuple_info, params->ip_type) == MATCHED) {
                return MATCHED;
            }
        }
    }
    return UNMATCHED;
}

static inline int match_src_ip(Istio__Security__Match *match, struct bpf_sock_tuple *tuple_info)
{
    if (!match || !tuple_info) {
        return UNMATCHED;
    }

    struct MatchIpParams params = {
        .tuple_info = tuple_info,
        .ip_list = match->source_ips,
        .not_ip_list = match->not_source_ips,
        .n_ips = match->n_source_ips,
        .n_not_ips = match->n_not_source_ips,
        .ip_type = TYPE_SRCIP,
    };
    return match_ip_common(&params);
}

static inline int match_dst_ip(Istio__Security__Match *match, struct bpf_sock_tuple *tuple_info)
{
    if (!match || !tuple_info) {
        return UNMATCHED;
    }

    struct MatchIpParams params = {
        .tuple_info = tuple_info,
        .ip_list = match->destination_ips,
        .not_ip_list = match->not_destination_ips,
        .n_ips = match->n_destination_ips,
        .n_not_ips = match->n_not_destination_ips,
        .ip_type = TYPE_DSTIP,
    };
    return match_ip_common(&params);
}

static inline int match_IPs(Istio__Security__Match *match, struct bpf_sock_tuple *tuple_info)
{
    return match_src_ip(match, tuple_info) && match_dst_ip(match, tuple_info);
}

static int match_check(Istio__Security__Match *match, struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    __u32 matchResult;

    // if multiple types are set, they are AND-ed, all matched is a match
    // todo: add other match types
    matchResult = match_dst_ports(match, info, tuple_info) && match_IPs(match, tuple_info);
    return matchResult;
}

bool need_tail_call_to_user(Istio__Security__Match *match)
{
    if (!match)
        return false;
    return match->n_namespaces || match->n_not_namespaces || match->n_principals || match->n_not_principals;
}

static int clause_match_check(
    Istio__Security__Clause *cl,
    struct xdp_info *info,
    struct bpf_sock_tuple *tuple_info,
    struct match_context *match_ctx)
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
        // Currently, xdp only matches port and ip. If a principal
        // or namespace type rule is configured, it needs to be sent
        // to userspace for authorization.
        if (need_tail_call_to_user(match)) {
            match_ctx->need_tailcall_to_userspace = true;
        }
    }
    return UNMATCHED;
}

static int rule_match_check(
    Istio__Security__Rule *rule,
    struct xdp_info *info,
    struct bpf_sock_tuple *tuple_info,
    struct match_context *match_ctx)
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
        if (clause_match_check(clause, info, tuple_info, match_ctx) == UNMATCHED) {
            return UNMATCHED;
        }
    }
    return MATCHED;
}

SEC("xdp_auth")
int policies_check(struct xdp_md *ctx)
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
        return XDP_PASS;
    }

    match_ctx = bpf_map_lookup_elem(&kmesh_tc_args, &tuple_key);
    if (!match_ctx) {
        return XDP_PASS;
    }

    policies = match_ctx->policies;
    if (!policies) {
        return XDP_PASS;
    }

    // Safely access policyId and check if the policy exists
    if (bpf_probe_read_kernel(&policyId, sizeof(policyId), (void *)(policies->policyIds + match_ctx->policy_index))
        != 0) {
        return XDP_PASS;
    }
    policy = map_lookup_authz(policyId);
    if (!policy) {
        // Currently, authz in xdp only support ip and port,
        // if any principal or namespace type policy is configured,
        // we need to tailcall to userspace.
        if (match_ctx->need_tailcall_to_userspace) {
            bpf_tail_call(ctx, &map_of_xdp_tailcall, TAIL_CALL_AUTH_IN_USER_SPACE);
            return XDP_PASS;
        }
        return match_ctx->auth_result;
    } else {
        rulesPtr = KMESH_GET_PTR_VAL(policy->rules, void *);
        if (!rulesPtr) {
            return XDP_PASS;
        }
        match_ctx->rulesPtr = rulesPtr;
        match_ctx->n_rules = policy->n_rules;
        match_ctx->action = policy->action;
        char *policy_name = (char *)KMESH_GET_PTR_VAL(policy->name, char *);
        if (!policy_name) {
            return XDP_PASS;
        }
        match_ctx->policy_name = policy_name;
        ret = bpf_map_update_elem(&kmesh_tc_args, &tuple_key, match_ctx, BPF_ANY);
        if (ret < 0) {
            return XDP_PASS;
        }
        bpf_tail_call(ctx, &map_of_xdp_tailcall, TAIL_CALL_POLICY_CHECK);
    }
    return XDP_PASS;
}

SEC("xdp_auth")
int policy_check(struct xdp_md *ctx)
{
    struct match_context *match_ctx;
    struct bpf_sock_tuple tuple_key = {0};
    struct xdp_info info = {0};
    bool matched = false;
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
            break;
        }
        if (!match_ctx) {
            return XDP_PASS;
        }
        rulesPtr = match_ctx->rulesPtr;
        if (!rulesPtr) {
            return XDP_PASS;
        }
        if (bpf_probe_read_kernel(&rule_addr, sizeof(rule_addr), &rulesPtr[i]) != 0) {
            continue;
        }

        rule = (Istio__Security__Rule *)KMESH_GET_PTR_VAL((void *)rule_addr, Istio__Security__Rule);
        if (!rule) {
            continue;
        }
        if (rule_match_check(rule, &info, &tuple_key, match_ctx) == MATCHED) {
            matched = true;
            break;
        }
    }

    if (matched) {
        BPF_LOG(DEBUG, AUTH, "policy %s matched", match_ctx->policy_name);
        if (info.iph->version == IPV4_VERSION) {
            BPF_LOG(
                DEBUG,
                AUTH,
                "src ip: %u, dst ip %u, dst port: %u\n",
                ip2str(&tuple_key.ipv4.saddr, true),
                ip2str(&tuple_key.ipv4.daddr, true),
                bpf_ntohs(tuple_key.ipv4.dport));
        } else {
            BPF_LOG(
                DEBUG,
                AUTH,
                "src ip: %u, dst ip %u, dst port: %u\n",
                ip2str(&tuple_key.ipv6.saddr[0], false),
                ip2str(&tuple_key.ipv6.daddr[0], false),
                bpf_ntohs(tuple_key.ipv6.dport));
        }
        if (bpf_map_delete_elem(&kmesh_tc_args, &tuple_key) != 0) {
            BPF_LOG(ERR, AUTH, "failed to delete tail call context from map");
        }
        __u32 auth_result = match_ctx->action == ISTIO__SECURITY__ACTION__DENY ? AUTH_DENY : AUTH_ALLOW;
        if (bpf_map_update_elem(&map_of_auth_result, &tuple_key, &auth_result, BPF_ANY) != 0) {
            BPF_LOG(ERR, AUTH, "failed to update auth result in map_of_auth_result");
        }
        return match_ctx->action == ISTIO__SECURITY__ACTION__DENY ? XDP_DROP : XDP_PASS;
    }
    if (match_ctx->auth_result == XDP_PASS) {
        match_ctx->auth_result = match_ctx->action == ISTIO__SECURITY__ACTION__DENY ? XDP_PASS : XDP_DROP;
    }
    match_ctx->policy_index++;

    ret = bpf_map_update_elem(&kmesh_tc_args, &tuple_key, match_ctx, BPF_ANY);
    if (ret < 0) {
        BPF_LOG(ERR, AUTH, "failed to update map, error: %d", ret);
        return XDP_PASS;
    }
    bpf_tail_call(ctx, &map_of_xdp_tailcall, TAIL_CALL_POLICIES_CHECK);
    return XDP_PASS;
}

#endif