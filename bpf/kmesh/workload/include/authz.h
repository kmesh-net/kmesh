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

struct match_ctx {
    __u32 action;
    void *match;
};

/*
 * This map is used to store the variable that
 * xdp_auth needs to pass during the tail call
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct bpf_sock_tuple));
    __uint(value_size, sizeof(struct match_ctx));
    __uint(max_entries, 256);
} tailcall_info_map SEC(".maps");

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

static inline int get_tuple_key(struct xdp_md *ctx, struct bpf_sock_tuple *tuple_info, struct xdp_info *info)
{
    int ret = parser_xdp_info(ctx, info);
    if (ret != PARSER_SUCC) {
        BPF_LOG(ERR, AUTH, "Failed to parse xdp_info\n");
        return PARSER_FAILED;
    }

    parser_tuple(info, tuple_info);

    return PARSER_SUCC;
}

SEC("xdp_auth")
int matchDstPorts(struct xdp_md *ctx)
{
    struct match_ctx *res;
    __u32 *notPorts = NULL;
    __u32 *ports = NULL;
    __u32 i;
    __u16 dport = 0;
    Istio__Security__Match *match = NULL;
    struct bpf_sock_tuple tuple_key = {0};
    struct xdp_info info = {0};
    int ret;

    if (get_tuple_key(ctx, &tuple_key, &info) != PARSER_SUCC) {
        BPF_LOG(ERR, AUTH, "Failed to get tuple key\n");
        return XDP_ABORTED;
    }

    res = bpf_map_lookup_elem(&tailcall_info_map, &tuple_key);
    if (!res) {
        BPF_LOG(ERR, AUTH, "Failed to retrieve res from map\n");
        return XDP_PASS;
    }

    if (info.iph->version == 4) {
        dport = tuple_key.ipv4.dport;
    } else if (info.ip6h->version == 6) {
        dport = tuple_key.ipv6.dport;
    } else {
        BPF_LOG(ERR, AUTH, "Invalid IP version.\n");
        return XDP_PASS;
    }
    match = (Istio__Security__Match *)kmesh_get_ptr_val(res->match);
    if (!match) {
        BPF_LOG(ERR, AUTH, "match pointer is null\n");
        return XDP_PASS;
    }

    if (match->n_destination_ports == 0 && match->n_not_destination_ports == 0) {
        return (res->action == AUTH_DENY) ? XDP_PASS : XDP_DROP;
    }

    if (match->n_not_destination_ports != 0) {
        notPorts = kmesh_get_ptr_val(match->not_destination_ports);
        if (!notPorts) {
            return (res->action == AUTH_DENY) ? XDP_PASS : XDP_DROP;
        }
#pragma unroll
        for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
            if (i >= match->n_not_destination_ports) {
                break;
            }
            if (bpf_htons(notPorts[i]) == dport) {
                if (res->action == AUTH_DENY) {
                    return XDP_PASS;
                } else {
                    BPF_LOG(INFO, AUTH, "Denied: dport %u matches \n", notPorts[i]);
                    return XDP_DROP;
                }
            }
        }
    }

    if (match->n_destination_ports == 0) {
        return (res->action == AUTH_DENY) ? XDP_DROP : XDP_PASS;
    }

    ports = kmesh_get_ptr_val(match->destination_ports);
    if (!ports) {
        return (res->action == AUTH_DENY) ? XDP_PASS : XDP_DROP;
    }

#pragma unroll
    for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
        if (i >= match->n_destination_ports) {
            break;
        }
        if (bpf_htons(ports[i]) == dport) {
            if (res->action == AUTH_DENY) {
                BPF_LOG(INFO, AUTH, "Denied: dport %u matches \n", ports[i]);
                return XDP_DROP;
            } else {
                return XDP_PASS;
            }
        }
    }

    bpf_tail_call(ctx, &xdp_tailcall_map, TAIL_CALL_AUTH_IN_USER_SPACE);
    return XDP_PASS;
}

static inline int match_check(struct xdp_md *ctx, void *match, Istio__Security__Action action)
{
    struct match_ctx res;
    struct bpf_sock_tuple tuple_key = {0};
    struct xdp_info info = {0};
    int ret;

    if (get_tuple_key(ctx, &tuple_key, &info) != PARSER_SUCC) {
        BPF_LOG(ERR, AUTH, "Failed to get tuple key\n");
        return XDP_ABORTED;
    }
    res.match = match;
    res.action = action;

    ret = bpf_map_update_elem(&tailcall_info_map, &tuple_key, &res, BPF_ANY);
    if (ret < 0) {
        BPF_LOG(ERR, AUTH, "Failed to update map, error: %d\n", ret);
        return XDP_DROP;
    }
    bpf_tail_call(ctx, &xdp_tailcall_map, TAIL_CALL_PORT_MATCH);
    return XDP_PASS;
}

static inline int clause_match_check(struct xdp_md *ctx, Istio__Security__Clause *cl, Istio__Security__Action action)
{
    void *matchsPtr = NULL;
    void *match = NULL;
    __u32 i;

    if (cl->n_matches == 0) {
        return UNMATCHED;
    }
    matchsPtr = kmesh_get_ptr_val(cl->matches);
    if (!matchsPtr) {
        return MATCHED;
    }

#pragma unroll
    for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
        if (i >= cl->n_matches) {
            break;
        }
        match = (void *)*((__u64 *)matchsPtr + i);
        if (!match) {
            continue;
        }
        // if any match matches, it is a match
        if (match_check(ctx, match, action) == MATCHED) {
            return MATCHED;
        }
    }
    return UNMATCHED;
}

static inline int rule_match_check(struct xdp_md *ctx, Istio__Security__Rule *rule, Istio__Security__Action action)
{
    void *clausesPtr = NULL;
    Istio__Security__Clause *clause = NULL;
    __u32 i;

    if (rule->n_clauses == 0) {
        BPF_LOG(ERR, AUTH, "rule has no clauses\n");
        return UNMATCHED;
    }
    // Clauses are AND-ed.
    clausesPtr = kmesh_get_ptr_val(rule->clauses);
    if (!clausesPtr) {
        BPF_LOG(ERR, AUTH, "failed to get clauses from rule\n");
        return UNMATCHED;
    }

#pragma unroll
    for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
        if (i >= rule->n_clauses) {
            break;
        }
        clause = (Istio__Security__Clause *)kmesh_get_ptr_val((void *)*((__u64 *)clausesPtr + i));
        if (!clause) {
            continue;
        }
        if (clause_match_check(ctx, clause, action) == UNMATCHED) {
            return UNMATCHED;
        }
    }
    return MATCHED;
}

static inline int do_auth(struct xdp_md *ctx, Istio__Security__Authorization *policy)
{
    void *rulesPtr = NULL;
    Istio__Security__Rule *rule = NULL;
    int matchFlag = 0;
    __u32 i = 0;

    if (policy->n_rules == 0) {
        BPF_LOG(ERR, AUTH, "auth policy %s has no rules\n", kmesh_get_ptr_val(policy->name));
        return AUTH_ALLOW;
    }

    // Rules are OR-ed.
    rulesPtr = kmesh_get_ptr_val(policy->rules);
    if (!rulesPtr) {
        BPF_LOG(ERR, AUTH, "failed to get rules from policy %s\n", kmesh_get_ptr_val(policy->name));
        return AUTH_DENY;
    }

    for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
        if (i >= policy->n_rules) {
            break;
        }
        rule = (Istio__Security__Rule *)kmesh_get_ptr_val((void *)*((__u64 *)rulesPtr + i));
        if (!rule) {
            continue;
        }
        if (rule_match_check(ctx, rule, policy->action) == MATCHED) {
            if (policy->action == ISTIO__SECURITY__ACTION__DENY) {
                return AUTH_DENY;
            } else {
                return AUTH_ALLOW;
            }
        }
    }

    // no match rules
    if (policy->action == ISTIO__SECURITY__ACTION__DENY) {
        return AUTH_ALLOW;
    } else {
        return AUTH_DENY;
    }
}

#endif