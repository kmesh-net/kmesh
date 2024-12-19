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
        BPF_LOG(WARN, SERVICE, "lb_random_handle select endpoint [%u/%u] failed", service_id, endpoint_k.backend_index);
        return -ENOENT;
    }

    BPF_LOG(DEBUG, SERVICE, "lb_random_handle select endpoint [%u/%u]", service_id, endpoint_k.backend_index);

    ret = endpoint_manager(kmesh_ctx, endpoint_v, service_id, service_v);
    if (ret != 0) {
        if (ret != -ENOENT)
            BPF_LOG(ERR, SERVICE, "endpoint_manager failed, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

// TODO: reuse with lb_random_handle
static inline int lb_locality_strict_handle(struct kmesh_context *kmesh_ctx, __u32 service_id, service_value *service_v)
{
    int ret = -ENOENT;
    endpoint_key endpoint_k = {0};
    endpoint_value *endpoint_v = NULL;
    endpoint_k.service_id = service_id;

    if (service_v->prio_endpoint_count[0]) {
        endpoint_k.backend_index = bpf_get_prandom_u32() % service_v->prio_endpoint_count[0] + 1;
        endpoint_v = map_lookup_endpoint(&endpoint_k);
        if (endpoint_v) {
            BPF_LOG(DEBUG, SERVICE, "locality lb strict select endpoint [%u/%u]", service_id, endpoint_k.backend_index);
            ret = endpoint_manager(kmesh_ctx, endpoint_v, service_id, service_v);
        }
    }

    if (ret) {
        kmesh_ctx->dnat_ip = (struct ip_addr){0};
        kmesh_ctx->dnat_port = 0;
        BPF_LOG(
            ERR, SERVICE, "locality loadbalance match nothing in STRICT mode, service_id %d ret:%d\n", service_id, ret);
    }
    return ret;
}

static inline int
lb_locality_failover_handle(struct kmesh_context *kmesh_ctx, __u32 service_id, service_value *service_v)
{
    int i, ret = -ENOENT;
    endpoint_key endpoint_k = {0};
    endpoint_value *endpoint_v = NULL;
    endpoint_k.service_id = service_id;

    // #pragma unroll
    for (i = 0; i < PRIO_COUNT; i++) {
        if (service_v->prio_endpoint_count[i] == 0)
            continue;

        endpoint_k.prio = i;
        endpoint_k.backend_index = bpf_get_prandom_u32() % service_v->prio_endpoint_count[i] + 1;
        endpoint_v = map_lookup_endpoint(&endpoint_k);
        if (!endpoint_v) {
            ret = -ENOENT;
            break;
        }

        BPF_LOG(
            DEBUG, SERVICE, "locality lb failover select endpoint [%u/%u/%u]", service_id, i, endpoint_k.backend_index);
        ret = endpoint_manager(kmesh_ctx, endpoint_v, service_id, service_v);
        break;
    }

    if (ret)
        BPF_LOG(ERR, SERVICE, "locality lb failover [%u:%u] failed:%d\n", service_id, kmesh_ctx->ctx->user_port, ret);
    return ret;
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

    BPF_LOG(DEBUG, SERVICE, "service [%u] lb policy [%u]", service_id, service_v->lb_policy);

    switch (service_v->lb_policy) {
    case LB_POLICY_RANDOM:
        ret = lb_random_handle(kmesh_ctx, service_id, service_v);
        break;
    case LB_POLICY_STRICT:
        ret = lb_locality_strict_handle(kmesh_ctx, service_id, service_v);
        break;
    case LB_POLICY_FAILOVER:
        ret = lb_locality_failover_handle(kmesh_ctx, service_id, service_v);
        break;
    default:
        BPF_LOG(ERR, SERVICE, "unsupported load balance type:%u\n", service_v->lb_policy);
        ret = -EINVAL;
        break;
    }

    return ret;
}

#endif
