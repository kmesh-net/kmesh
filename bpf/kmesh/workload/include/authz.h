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

struct match_result {
    __u32 action;
    __u32 match_res;
    __u16 dport;
    struct bpf_sock_tuple *tuple_info;
    void *match;
};

/*
 * This map is used to store the variable that
 * xdp_auth needs to pass during the tail call
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct match_result));
    __uint(max_entries, 1);
} map_of_t_data SEC(".maps");

static inline Istio__Security__Authorization *map_lookup_authz(__u32 policyKey)
{
    return (Istio__Security__Authorization *)kmesh_map_lookup_elem(&map_of_authz, &policyKey);
}

static inline wl_policies_v *get_workload_policies_by_uid(__u32 workload_uid)
{
    return (wl_policies_v *)kmesh_map_lookup_elem(&map_of_wl_policy, &workload_uid);
}

SEC("xdp_auth")
int matchDstPorts(struct xdp_md *ctx)
{
    struct match_result *res;
    __u32 key = 0;
    __u32 *notPorts = NULL;
    __u32 *ports = NULL;
    __u32 i;
    __u16 dport; // Destination port
    Istio__Security__Match *match = NULL;

    res = bpf_map_lookup_elem(&map_of_t_data, &key);
    if (!res) {
        BPF_LOG(ERR, AUTH, "Failed to retrieve res from map\n");
        return XDP_PASS;
    }
    dport = res->dport;

    match = (Istio__Security__Match *)kmesh_get_ptr_val(res->match);
    if (!match) {
        BPF_LOG(ERR, AUTH, "match pointer is null\n");
        return XDP_PASS;
    }

    if (match->n_destination_ports == 0 && match->n_not_destination_ports == 0) {
        res->match_res = MATCHED;
        goto check_action;
    }

    if (match->n_not_destination_ports != 0) {
        notPorts = kmesh_get_ptr_val(match->not_destination_ports);
        if (!notPorts) {
            res->match_res = UNMATCHED;
            goto check_action;
        }
#pragma unroll
        for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
            if (i >= match->n_not_destination_ports) {
                break;
            }
            if (bpf_htons(notPorts[i]) == dport) {
                res->match_res = UNMATCHED;
                BPF_LOG(INFO, AUTH, "Denyed: dport %u matches \n", notPorts[i]);
                goto check_action;
            }
        }
    }

    if (match->n_destination_ports == 0) {
        res->match_res = MATCHED;
        goto check_action;
    }

    ports = kmesh_get_ptr_val(match->destination_ports);
    if (!ports) {
        res->match_res = UNMATCHED;
        goto check_action;
    }

#pragma unroll
    for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
        if (i >= match->n_destination_ports) {
            break;
        }
        if (bpf_htons(ports[i]) == dport) {
            res->match_res = MATCHED;
            BPF_LOG(INFO, AUTH, "Denyed: dport %u matches \n", ports[i]);
            goto check_action;
        }
    }

    res->match_res = UNMATCHED;
    return XDP_PASS;

check_action:
    return (res->action == AUTH_DENY) ? (res->match_res == MATCHED ? XDP_DROP : XDP_PASS) :
                                        (res->match_res == MATCHED ? XDP_PASS : XDP_DROP);
}

static inline int match_check(struct xdp_md *ctx, void *match, struct bpf_sock_tuple *tuple_info)
{
    __u32 key = 0;
    struct match_result *res;

    res = bpf_map_lookup_elem(&map_of_t_data, &key);
    if (!res) {
        BPF_LOG(ERR, AUTH, "Failed to lookup map element\n");
        return XDP_DROP;
    }

    res->match_res = UNMATCHED;
    res->match = match;

    int ret = bpf_map_update_elem(&map_of_t_data, &key, res, BPF_ANY);
    if (ret < 0) {
        BPF_LOG(ERR, AUTH, "Failed to update map, error: %d\n", ret);
        return XDP_DROP;
    }

    bpf_tail_call(ctx, &map_of_tail_call_prog_for_xdp, TAIL_CALL_PORT_MATCH);
    return XDP_PASS;
}

static inline int clause_match_check(struct xdp_md *ctx, Istio__Security__Clause *cl, struct bpf_sock_tuple *tuple_info)
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
        if (match_check(ctx, match, tuple_info) == MATCHED) {
            return MATCHED;
        }
    }
    return UNMATCHED;
}

static inline int rule_match_check(struct xdp_md *ctx, Istio__Security__Rule *rule, struct bpf_sock_tuple *tuple_info)
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
        if (clause_match_check(ctx, clause, tuple_info) == UNMATCHED) {
            return UNMATCHED;
        }
    }
    return MATCHED;
}

static inline int do_auth(
    struct xdp_md *ctx,
    Istio__Security__Authorization *policy,
    struct xdp_info *info,
    struct bpf_sock_tuple *tuple_info)
{
    void *rulesPtr = NULL;
    Istio__Security__Rule *rule = NULL;
    int matchFlag = 0;
    __u32 i = 0;
    __u32 key = 0;
    struct match_result res;

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

    res.action = policy->action;
    res.tuple_info = tuple_info;
    if (info->iph->version == 4) {
        res.dport = tuple_info->ipv4.dport;
    } else {
        res.dport = tuple_info->ipv6.dport;
    }
    bpf_map_update_elem(&map_of_t_data, &key, &res, BPF_ANY);

    for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
        if (i >= policy->n_rules) {
            break;
        }
        rule = (Istio__Security__Rule *)kmesh_get_ptr_val((void *)*((__u64 *)rulesPtr + i));
        if (!rule) {
            continue;
        }
        if (rule_match_check(ctx, rule, tuple_info) == MATCHED) {
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