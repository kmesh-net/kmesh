/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __KMESH_SERVICE_H__
#define __KMESH_SERVICE_H__

#include "workload_common.h"
#include "endpoint.h"

static inline service_value *map_lookup_service(const service_key *key)
{
    return kmesh_map_lookup_elem(&map_of_service, key);
}

static inline int lb_random_handle(struct kmesh_context *kmesh_ctx, __u32 service_id, service_value *service_v)
{
    int ret = 0;
    endpoint_key endpoint_k = {0};
    endpoint_value *endpoint_v = NULL;
    int rand_k = 0;

    if (service_v->prio_endpoint_count[0] == 0)
        return 0;

    endpoint_k.service_id = service_id;
    endpoint_k.prio = 0; // for random handle，all endpoints are saved with highest priority

    rand_k = bpf_get_prandom_u32() % service_v->prio_endpoint_count[0] + 1;
    endpoint_k.backend_index = rand_k;

    endpoint_v = map_lookup_endpoint(&endpoint_k);
    if (!endpoint_v) {
        BPF_LOG(WARN, SERVICE, "find endpoint [%u/%u] failed", service_id, endpoint_k.backend_index);
        return -ENOENT;
    }

    ret = endpoint_manager(kmesh_ctx, endpoint_v, service_id, service_v);
    if (ret != 0) {
        if (ret != -ENOENT)
            BPF_LOG(ERR, SERVICE, "endpoint_manager failed, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

static inline int
lb_locality_failover_handle(struct kmesh_context *kmesh_ctx, __u32 service_id, service_value *service_v, bool is_strict)
{
    int ret = 0;
    uint32_t rand_k = 0;
    endpoint_key endpoint_k = {0};
    endpoint_value *endpoint_v = NULL;
    endpoint_k.service_id = service_id;
    struct ip_addr zero_addr = {0};
    __u32 zero_port = 0;

    // #pragma unroll
    for (int match_prio = 0; match_prio < PRIO_COUNT; match_prio++) {
        endpoint_k.prio = match_prio; // 0->6
        // if we have endpoints in this prio
        if (service_v->prio_endpoint_count[match_prio] > 0) {
            rand_k = bpf_get_prandom_u32() % service_v->prio_endpoint_count[match_prio] + 1;
            if (rand_k >= MAP_SIZE_OF_BACKEND) {
                return -ENOENT;
            }
            endpoint_k.backend_index = rand_k;
            endpoint_v = map_lookup_endpoint(&endpoint_k);
            if (!endpoint_v) {
                BPF_LOG(
                    ERR, SERVICE, "find endpoint [%u/%u/%u] failed", service_id, match_prio, endpoint_k.backend_index);
                return -ENOENT;
            }
            ret = endpoint_manager(kmesh_ctx, endpoint_v, service_id, service_v);
            if (ret != 0) {
                if (ret != -ENOENT)
                    BPF_LOG(ERR, SERVICE, "endpoint_manager failed, ret:%d\n", ret);
                return ret;
            }
            BPF_LOG(DEBUG, SERVICE, "locality loadbalance matched backend_uid %d\n", endpoint_v->backend_uid);
            return 0; // find the backend successfully
        }
        if (is_strict) { // only match max priority in strict mode
            kmesh_ctx->dnat_ip = zero_addr;
            kmesh_ctx->dnat_port = zero_port;
            BPF_LOG(DEBUG, SERVICE, "locality loadbalance match nothing in STRICT mode\n");
            return -ENOENT;
        }
    }
    // no backend matched
    return -ENOENT;
}

static inline int service_manager(struct kmesh_context *kmesh_ctx, __u32 service_id, service_value *service_v)
{
    int ret = 0;

    if (service_v->wp_addr.ip4 != 0 && service_v->waypoint_port != 0) {
        BPF_LOG(
            DEBUG,
            SERVICE,
            "find waypoint addr=[%s:%u]\n",
            ip2str((__u32 *)&service_v->wp_addr, kmesh_ctx->ctx->family == AF_INET),
            bpf_ntohs(service_v->waypoint_port));
        ret = waypoint_manager(kmesh_ctx, &service_v->wp_addr, service_v->waypoint_port);
        if (ret != 0) {
            BPF_LOG(ERR, BACKEND, "waypoint_manager failed, ret:%d\n", ret);
        }
        return ret;
    }

    BPF_LOG(DEBUG, SERVICE, "service [%u] policy [%u] failed", service_id, service_v->lb_policy);

    switch (service_v->lb_policy) {
    case LB_POLICY_RANDOM:
        ret = lb_random_handle(kmesh_ctx, service_id, service_v);
        break;
    case LB_POLICY_STRICT:
        ret = lb_locality_failover_handle(kmesh_ctx, service_id, service_v, true);
        break;
    case LB_POLICY_FAILOVER:
        ret = lb_locality_failover_handle(kmesh_ctx, service_id, service_v, false);
        break;
    default:
        BPF_LOG(ERR, SERVICE, "unsupported load balance type:%u\n", service_v->lb_policy);
        ret = -EINVAL;
        break;
    }

    return ret;
}

#endif
