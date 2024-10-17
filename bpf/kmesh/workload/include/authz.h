/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __AUTHZ_H__
#define __AUTHZ_H__

#include "workload_common.h"
#include "bpf_log.h"
#include "xdp.h"
#include "tail_call.h"
#include "workloadapi/security/authorization.pb-c.h"

#define AUTH_ALLOW 0
#define AUTH_DENY  1
#define UNMATCHED  0
#define MATCHED    1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(Istio__Security__Authorization));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_AUTH_POLICY);
} map_of_authz SEC(".maps");

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
} kmesh_tc_info_map SEC(".maps");

static inline Istio__Security__Authorization *map_lookup_authz(__u32 policyKey)
{
    return (Istio__Security__Authorization *)kmesh_map_lookup_elem(&map_of_authz, &policyKey);
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
    if (((struct iphdr *)begin)->version == 4) {
        info->iph = (struct iphdr *)begin;
        if ((void *)(info->iph + 1) > end || (info->iph->protocol != IPPROTO_TCP))
            return PARSER_FAILED;
        begin = (info->iph + 1);
    } else if (((struct iphdr *)begin)->version == 6) {
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

static int construct_tuple_key(struct xdp_md *ctx, struct bpf_sock_tuple *tuple_info, struct xdp_info *info)
{
    int ret = parser_xdp_info(ctx, info);
    if (ret != PARSER_SUCC) {
        BPF_LOG(ERR, AUTH, "Failed to parse xdp_info");
        return PARSER_FAILED;
    }

    parser_tuple(info, tuple_info);

    return PARSER_SUCC;
}

static int matchDstPorts(Istio__Security__Match *match, struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    __u32 *notPorts = NULL;
    __u32 *ports = NULL;
    __u32 i;

    if (match->n_destination_ports == 0 && match->n_not_destination_ports == 0) {
        BPF_LOG(DEBUG, AUTH, "No ports configured, matching by default");
        return MATCHED;
    }

    if (match->n_not_destination_ports != 0) {
        notPorts = KMESH_GET_PTR_VAL(match->not_destination_ports, void *);
        if (!notPorts) {
            BPF_LOG(ERR, AUTH, "Failed to retrieve not_destination_ports pointer");
            return UNMATCHED;
        }
#pragma unroll
        for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
            if (i >= match->n_not_destination_ports) {
                break;
            }
            if (info->iph->version == 4) {
                if (bpf_htons(notPorts[i]) == tuple_info->ipv4.dport) {
                    BPF_LOG(DEBUG, AUTH, "Port %u in not_destination_ports, unmatched", notPorts[i]);
                    return UNMATCHED;
                }
            } else {
                if (bpf_htons(notPorts[i]) == tuple_info->ipv6.dport) {
                    BPF_LOG(DEBUG, AUTH, "Port %u in not_destination_ports, unmatched", notPorts[i]);
                    return UNMATCHED;
                }
            }
        }
    }
    // if not match not_destination_ports && has no destination_ports, return MATCHED
    if (match->n_destination_ports == 0) {
        BPF_LOG(INFO, AUTH, "No destination_ports configured, matching by default");
        return MATCHED;
    }

    ports = KMESH_GET_PTR_VAL(match->destination_ports, void *);
    if (!ports) {
        BPF_LOG(ERR, AUTH, "Failed to retrieve destination_ports pointer");
        return UNMATCHED;
    }
#pragma unroll
    for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
        if (i >= match->n_destination_ports) {
            break;
        }
        if (info->iph->version == 4) {
            if (bpf_htons(ports[i]) == tuple_info->ipv4.dport) {
                BPF_LOG(INFO, AUTH, "Port %u in destination_ports, matched", ports[i]);
                return MATCHED;
            }
        } else {
            if (bpf_htons(ports[i]) == tuple_info->ipv6.dport) {
                BPF_LOG(INFO, AUTH, "Port %u in destination_ports, matched", ports[i]);
                return MATCHED;
            }
        }
    }
    BPF_LOG(DEBUG, AUTH, "No matching ports found, unmatched");
    return UNMATCHED;
}

static int match_check(Istio__Security__Match *match, struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    __u32 matchResult;

    // if multiple types are set, they are AND-ed, all matched is a match
    // todo: add other match types
    matchResult = matchDstPorts(match, info, tuple_info);
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
        BPF_LOG(ERR, AUTH, "rule has no clauses\n");
        return UNMATCHED;
    }
    // Clauses are AND-ed.
    clausesPtr = KMESH_GET_PTR_VAL(rule->clauses, void *);
    if (!clausesPtr) {
        BPF_LOG(ERR, AUTH, "failed to get clauses from rule\n");
        return UNMATCHED;
    }

#pragma unroll
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
        return XDP_ABORTED;
    }

    match_ctx = bpf_map_lookup_elem(&kmesh_tc_info_map, &tuple_key);
    if (!match_ctx) {
        BPF_LOG(ERR, AUTH, "Failed to retrieve tailcall context from kmesh_tc_info_map");
        return XDP_PASS;
    }

    policies = match_ctx->policies;
    if (!policies) {
        return XDP_PASS;
    }

    // Safely access policyId and check if the policy exists
    if (bpf_probe_read_kernel(&policyId, sizeof(policyId), (void *)(policies->policyIds + match_ctx->policy_index))
        != 0) {
        BPF_LOG(ERR, AUTH, "Failed to read policyId, throw it to user auth");
        if (bpf_map_delete_elem(&kmesh_tc_info_map, &tuple_key) != 0) {
            BPF_LOG(DEBUG, AUTH, "Failed to delete context from map");
        }
        bpf_tail_call(ctx, &xdp_tailcall_map, TAIL_CALL_AUTH_IN_USER_SPACE);
    }
    policy = map_lookup_authz(policyId);
    if (!policy) {
        // if no policy matches in xdp, thrown it to user auth
        if (bpf_map_delete_elem(&kmesh_tc_info_map, &tuple_key) != 0) {
            BPF_LOG(DEBUG, AUTH, "Failed to delete tailcall context from map");
        }
        bpf_tail_call(ctx, &xdp_tailcall_map, TAIL_CALL_AUTH_IN_USER_SPACE);
    } else {
        rulesPtr = kmesh_get_ptr_val(policy->rules);
        if (!rulesPtr) {
            BPF_LOG(ERR, AUTH, "failed to get rules from policy %s\n", kmesh_get_ptr_val(policy->name));
            return XDP_DROP;
        }
        match_ctx->rulesPtr = rulesPtr;
        match_ctx->n_rules = policy->n_rules;
        match_ctx->action = policy->action;
        ret = bpf_map_update_elem(&kmesh_tc_info_map, &tuple_key, match_ctx, BPF_ANY);
        if (ret < 0) {
            BPF_LOG(ERR, AUTH, "Failed to update map, error: %d", ret);
            return XDP_DROP;
        }
        bpf_tail_call(ctx, &xdp_tailcall_map, TAIL_CALL_RULE_CHECK);
    }
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
        BPF_LOG(ERR, AUTH, "Failed to get tuple key in rule_check");
        return XDP_ABORTED;
    }

    match_ctx = bpf_map_lookup_elem(&kmesh_tc_info_map, &tuple_key);
    if (!match_ctx) {
        BPF_LOG(ERR, AUTH, "Failed to retrieve match_context from map");
        return XDP_PASS;
    }
    for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
        if (i >= match_ctx->n_rules) {
            BPF_LOG(DEBUG, AUTH, "Rule index %d exceeds rule count %d, exiting loop", i, match_ctx->n_rules);
            break;
        }
        if (!match_ctx) {
            BPF_LOG(ERR, AUTH, "Failed to retrieve match_ctx from map");
            return XDP_PASS;
        }
        rulesPtr = match_ctx->rulesPtr;
        if (!rulesPtr) {
            BPF_LOG(ERR, AUTH, "rulesPtr is null");
            return XDP_PASS;
        }
        if (bpf_probe_read_kernel(&rule_addr, sizeof(rule_addr), &rulesPtr[i]) != 0) {
            BPF_LOG(ERR, AUTH, "Failed to read rule address at index %d", i);
            continue;
        }

        rule = (Istio__Security__Rule *)kmesh_get_ptr_val((void *)rule_addr);
        if (!rule) {
            continue;
        }
        if (rule_match_check(rule, &info, &tuple_key) == MATCHED) {
            if (match_ctx->action == ISTIO__SECURITY__ACTION__DENY) {
                BPF_LOG(INFO, AUTH, "Rule matched, action: DENY");
                if (bpf_map_delete_elem(&kmesh_tc_info_map, &tuple_key) != 0) {
                    BPF_LOG(DEBUG, AUTH, "Failed to delete context from map");
                }
                return AUTH_DENY;
            } else {
                BPF_LOG(INFO, AUTH, "Rule matched, action: ALLOW");
                if (bpf_map_delete_elem(&kmesh_tc_info_map, &tuple_key) != 0) {
                    BPF_LOG(DEBUG, AUTH, "Failed to delete context from map");
                }
                return AUTH_ALLOW;
            }
        }
    }

    match_ctx->policy_index++;
    if (match_ctx->policy_index >= MAX_MEMBER_NUM_PER_POLICY) {
        BPF_LOG(ERR, AUTH, "Policy index out of bounds");
        bpf_tail_call(ctx, &xdp_tailcall_map, TAIL_CALL_AUTH_IN_USER_SPACE);
    }

    ret = bpf_map_update_elem(&kmesh_tc_info_map, &tuple_key, match_ctx, BPF_ANY);
    if (ret < 0) {
        BPF_LOG(ERR, AUTH, "Failed to update map, error: %d", ret);
        return XDP_DROP;
    }
    bpf_tail_call(ctx, &xdp_tailcall_map, TAIL_CALL_POLICY_CHECK);
    return XDP_PASS;
}

#endif