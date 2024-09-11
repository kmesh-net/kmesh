/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __AUTHZ_H__
#define __AUTHZ_H__

#include "workload_common.h"
#include "bpf_log.h"
#include "xdp.h"
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

	BPF_LOG(ERR, AUTH, "ip:%u.%u.%u.%u\n", data[0], data[1], data[2], data[3]);
	return (data[3] << 24) |
		   (data[2] << 16) |
		   (data[1] << 8)  |
		   (data[0] << 0);
}

static inline int matchIpv4(__u32 ruleIp, __u32 preFixLen, __be32 targetIP)
{
	__u32 mask = 0;

	if (preFixLen > 32) {
		return UNMATCHED;
	}

	mask = 0xFFFFFFFF >> (32 - preFixLen);
	BPF_LOG(ERR, KMESH, "mask = %u, ruleIp & mask = %u, targetIP & mask = %u\n", mask, ruleIp & mask, targetIP & mask);
	if ((ruleIp & mask) == (targetIP & mask)) {
		BPF_LOG(DEBUG, KMESH, "match it\n");
		return MATCHED;
	}
	return 0;
}

static inline int matchIp(struct ProtobufCBinaryData *addrInfo, __u32 preFixLen, struct bpf_sock_tuple *tuple_info, __u8 type)
{
	if (addrInfo->len == 4) {
		if (type & TYPE_SRCIP) {
			return matchIpv4(convert_ipv4_to_u32(addrInfo), preFixLen, tuple_info->ipv4.saddr);
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
			// todo: ProtobufCBinaryData address是否需要使用mesh_get_ptr_val
			BPF_LOG(ERR, AUTH, "srcAddr->length = %u\n", srcAddr->length);
			if (matchIp(&srcAddr->address, srcAddr->length, tuple_info, TYPE_SRCIP) == MATCHED) {
				return MATCHED;
			}
		}
	}
	return UNMATCHED;
}
#endif

static inline int matchDstPorts(Istio__Security__Match *match, struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    __u32 *notPorts = NULL;
    __u32 *ports = NULL;
    __u32 i;

    if (match->n_destination_ports == 0 && match->n_not_destination_ports == 0) {
        return MATCHED;
    }

    if (match->n_not_destination_ports != 0) {
        notPorts = kmesh_get_ptr_val(match->not_destination_ports);
        if (!notPorts) {
            return UNMATCHED;
        }
#pragma unroll
        for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
            if (i >= match->n_not_destination_ports) {
                break;
            }
            if (info->iph->version == 4) {
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

    ports = kmesh_get_ptr_val(match->destination_ports);
    if (!ports) {
        return UNMATCHED;
    }
#pragma unroll
    for (i = 0; i < MAX_MEMBER_NUM_PER_POLICY; i++) {
        if (i >= match->n_destination_ports) {
            break;
        }
        if (info->iph->version == 4) {
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

static inline int match_check(Istio__Security__Match *match, struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    if (!matchDstPorts(match, info, tuple_info)) {
        BPF_LOG(INFO, AUTH, "match dstport!, port is %u\n", bpf_ntohs(tuple_info->ipv4.sport));
        return MATCHED;
    }

    if (!matchSrcIPs(match, tuple_info)) {
        BPF_LOG(INFO, AUTH, "match srcIP!, IP is %s\n", ip2str(&tuple_info->ipv4.saddr,true));
        return MATCHED;
    }
    return UNMATCHED;
}

static inline int
clause_match_check(Istio__Security__Clause *cl, struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
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
        if (match_check(match, info, tuple_info) == MATCHED) {
            return MATCHED;
        }
    }
    return UNMATCHED;
}

static inline int
rule_match_check(Istio__Security__Rule *rule, struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
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
        if (clause_match_check(clause, info, tuple_info) == UNMATCHED) {
            return UNMATCHED;
        }
    }
    return MATCHED;
}

static inline int
do_auth(Istio__Security__Authorization *policy, struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
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
        if (rule_match_check(rule, info, tuple_info) == MATCHED) {
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
