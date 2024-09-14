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
#define SUPPORT_IP_MATCH 1
#define TYPE_SRCIP   (1)
#define TYPE_DSTIP   (1 << 1)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(Istio__Security__Authorization));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_AUTH_POLICY);
} map_of_authz SEC(".maps");

struct match_result {
    __u32 action;      // Action: deny or allow
    __u32 match_res;    // Match result: true or false
    __u16 dport;
    Istio__Security__Match *match;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct match_result));
    __uint(max_entries, 1);
} map_of_shared_data SEC(".maps");

static inline Istio__Security__Authorization *map_lookup_authz(__u32 policyKey)
{
    return (Istio__Security__Authorization *)kmesh_map_lookup_elem(&map_of_authz, &policyKey);
}

static inline wl_policies_v *get_workload_policies_by_uid(__u32 workload_uid)
{
    return (wl_policies_v *)kmesh_map_lookup_elem(&map_of_wl_policy, &workload_uid);
}

#ifdef SUPPORT_IP_MATCH
static inline __u32 convert_ipv4_to_u32(const struct ProtobufCBinaryData *ipv4_data)
{
	if (!ipv4_data->data || ipv4_data->len != 4) {
		return 0;
	}

	unsigned char *data = kmesh_get_ptr_val(ipv4_data->data);
	if (!data) {
		return 0;
	}

	return (data[3] << 24) |
		   (data[2] << 16) |
		   (data[1] << 8)  |
		   (data[0] << 0);
}


static inline __u32 convert_ipv6_to_u32(struct ip_addr *rule_addr, const struct ProtobufCBinaryData *ipv6_data)
{
	if (!ipv6_data->data || ipv6_data->len != 16) {
		return 1;
	}

	unsigned char *v6addr = kmesh_get_ptr_val(ipv6_data->data);
	if (!v6addr) {
		return 1;
	}

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			rule_addr->ip6[i] |= (v6addr[i * 4 + j] << (i * 8));
		}
	}

	return 0;
}

static inline int matchIpv4(__u32 ruleIp, __u32 preFixLen, __be32 targetIP)
{
	__u32 mask = 0;

	if (preFixLen > 32) {
		return UNMATCHED;
	}

	mask = 0xFFFFFFFF >> (32 - preFixLen);
	if ((ruleIp & mask) == (targetIP & mask)) {
		BPF_LOG(DEBUG, KMESH, "match ipv4\n");
		return MATCHED;
	}
	return 0;
}

// reference cilium https://github.com/cilium/cilium/blob/main/bpf/lib/ipv6.h#L122
#define GET_PREFIX(PREFIX)						\
	bpf_htonl(PREFIX <= 0 ? 0 : PREFIX < 32 ? ((1<<PREFIX) - 1) << (32-PREFIX)	\
			      : 0xFFFFFFFF)

static inline void ipv6_addr_clear_suffix(union v6addr *addr,
						   int prefix)
{
	addr->p1 &= GET_PREFIX(prefix);
	prefix -= 32;
	addr->p2 &= GET_PREFIX(prefix);
	prefix -= 32;
	addr->p3 &= GET_PREFIX(prefix);
	prefix -= 32;
	addr->p4 &= GET_PREFIX(prefix);
}

static inline int matchIpv6(struct ip_addr *rule_addr, struct ip_addr *target_addr, __u32 prefixLen)
{
	if (prefixLen > 128)
		return UNMATCHED;

	ipv6_addr_clear_suffix(target_addr, prefixLen);
	if (rule_addr->ip6[0] == target_addr->ip6[0] &&
		rule_addr->ip6[1] == target_addr->ip6[1] &&
		rule_addr->ip6[2] == target_addr->ip6[2] &&
		rule_addr->ip6[3] == target_addr->ip6[3]) {
        BPF_LOG(DEBUG, KMESH, "match ipv6\n");
		return MATCHED;
	}

	return UNMATCHED;
}

static inline int matchIp(struct ProtobufCBinaryData *addrInfo, __u32 preFixLen, struct bpf_sock_tuple *tuple_info, __u8 type)
{
	if (addrInfo->len == 4) {
		if (type & TYPE_SRCIP) {
			return matchIpv4(convert_ipv4_to_u32(addrInfo), preFixLen, tuple_info->ipv4.saddr);
		} 
	} else if (addrInfo->len == 16) {
		if (type & TYPE_SRCIP) {
			struct ip_addr rule_addr = {0};
			struct ip_addr target_addr = {0};
			int ret = convert_ipv6_to_u32(&rule_addr, addrInfo);
			if (ret != 0) {
				BPF_LOG(ERR, AUTH, "failed to convert ipv6 addr to u32 format\n");
			}
			IP6_COPY(target_addr.ip6, tuple_info->ipv6.saddr);
			return matchIpv6(&rule_addr, &target_addr, preFixLen);
		}
	}
	return UNMATCHED;
}

static inline int matchSrcIPs(Istio__Security__Match *match, struct bpf_sock_tuple *tuple_info)
{
	void *srcPtrs = NULL;
	void *notSrcPtrs = NULL;
	__u32 inSrcList = 0;
	__u32 i;

	if (match->n_source_ips == 0 && match->n_not_source_ips == 0) {
		return MATCHED;
	}

	// match not_srcIPs
	if (match->n_not_source_ips != 0) {
		notSrcPtrs = kmesh_get_ptr_val(match->not_source_ips);
		if (!notSrcPtrs) {
			BPF_LOG(ERR, AUTH, "failed to get not_srcips ptr\n");
			return UNMATCHED;
		}

#pragma unroll   
		for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
			if (i >= match-> n_not_source_ips) {
				break;
			}
			Istio__Security__Address *srcAddr = (Istio__Security__Address *)kmesh_get_ptr_val((void *)*((__u64 *)notSrcPtrs + i));
			if (!srcAddr) {
				continue;
			}
			// todo: ProtobufCBinaryData address是否需要使用mesh_get_ptr_val
			// in n_src_ips means in blacklist, return unmatch
			if (matchIp(&srcAddr->address, srcAddr->length, tuple_info, TYPE_SRCIP) == MATCHED) {
				return UNMATCHED;
			}  
		}
	}

	if (match->n_source_ips != 0) {
		srcPtrs = kmesh_get_ptr_val(match->source_ips);
		if (!srcPtrs) {
			BPF_LOG(ERR, AUTH, "failed to get srcips ptr\n");
			return UNMATCHED;
		}

#pragma unroll   
		for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
			if (i >= match->n_source_ips) {
				break;
			}
			Istio__Security__Address *srcAddr = (Istio__Security__Address *)kmesh_get_ptr_val((void *)*((__u64 *)srcPtrs + i));
			if (!srcAddr) {
				continue;
			}
			if (matchIp(&srcAddr->address, srcAddr->length, tuple_info, TYPE_SRCIP) == MATCHED) {
				return MATCHED;
			}
		}
	}
	return UNMATCHED;
}
#endif

SEC("xdp_auth")
int matchDstPorts(struct xdp_md *ctx)
{
    struct match_result *res;
    __u32 key = 0;
    __u32 *notPorts = NULL;
    __u32 *ports = NULL;
    __u32 i;
    __u16 dport; // Destination port

    // Fetch the data from the shared BPF map
    res = bpf_map_lookup_elem(&map_of_shared_data, &key);
    if (!res) {
        return XDP_DROP;
    }

    if (!res->match) {
        return XDP_DROP;
    }

    Istio__Security__Match *match = kmesh_get_ptr_val(res->match);
    if (!match) {
        return XDP_DROP;
    }

    dport = res->dport;

    // Check if no destination ports are defined
    if (match->n_destination_ports == 0 && match->n_not_destination_ports == 0) {
        res->match_res = MATCHED;
        goto check_action;
    }

    // Check the not_destination_ports array
    if (match && match->n_not_destination_ports != 0) {
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
            // Check the not_destination_ports based on IP version
            if (bpf_htons(notPorts[i]) == dport) {
                res->match_res = UNMATCHED;
                goto check_action;
            }
        }
    }

    // If there are no destination ports to match, set result as matched
    if (match && match->n_destination_ports == 0) {
        res->match_res = MATCHED;
        goto check_action;
    }

    if (!match) {
        return XDP_DROP;
    }
    // Check the destination_ports array
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
        // Check the destination_ports based on IP version
        if (bpf_htons(ports[i]) == dport) {
            res->match_res = MATCHED;
            goto check_action;
        }
    }

    // If no ports matched, set result as unmatched
    res->match_res = UNMATCHED;

check_action:
    // Check the action and return corresponding XDP result
    return (res->action == AUTH_DENY) ? (res->match_res == MATCHED ? XDP_DROP : XDP_PASS) : (res->match_res == MATCHED ? XDP_PASS : XDP_DROP);
}


static inline int match_check(struct xdp_md *ctx, Istio__Security__Match *match, struct bpf_sock_tuple *tuple_info)
{
    __u32 key = 0;
    struct match_result res;
    res.match_res = UNMATCHED; 
    res.match = match;  

    int ret = bpf_map_update_elem(&map_of_shared_data, &key, &res, BPF_ANY);
    if (ret < 0) {
        return XDP_DROP;
    }
    bpf_tail_call(ctx, &map_of_tail_call_prog_for_xdp, TAIL_CALL_PORT_MATCH);
}

static inline int
clause_match_check(struct xdp_md *ctx, Istio__Security__Clause *cl, struct bpf_sock_tuple *tuple_info)
{
    void *matchsPtr = NULL;
    Istio__Security__Match *match = NULL;
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
        match = (Istio__Security__Match *)kmesh_get_ptr_val((void *)*((__u64 *)matchsPtr + i));
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

static inline int
rule_match_check(struct xdp_md *ctx, Istio__Security__Rule *rule, struct bpf_sock_tuple *tuple_info)
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

static inline int
do_auth(struct xdp_md *ctx, Istio__Security__Authorization *policy, struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
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
    if (info->iph->version == 4) {
        res.dport = tuple_info->ipv4.dport;
    } else {
        res.dport = tuple_info->ipv6.dport;
    }
    bpf_map_update_elem(&map_of_shared_data, &key, &res, BPF_ANY);

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
