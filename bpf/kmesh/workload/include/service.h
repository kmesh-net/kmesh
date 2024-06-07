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

static inline int lb_random_handle(ctx_buff_t *ctx, __u32 service_id, service_value *service_v)
{
    int ret = 0;
    endpoint_key endpoint_k = {0};
    endpoint_value *endpoint_v = NULL;

    endpoint_k.service_id = service_id;
    endpoint_k.backend_index = bpf_get_prandom_u32() % service_v->endpoint_count + 1;

    endpoint_v = map_lookup_endpoint(&endpoint_k);
    if (!endpoint_v) {
        BPF_LOG(WARN, SERVICE, "find endpoint [%u/%u] failed", service_id, endpoint_k.backend_index);
        return -ENOENT;
    }

    ret = endpoint_manager(ctx, endpoint_v, service_id, service_v);
    if (ret != 0) {
        if (ret != -ENOENT)
            BPF_LOG(ERR, SERVICE, "endpoint_manager failed, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

static inline int service_manager(ctx_buff_t *ctx, __u32 service_id, service_value *service_v)
{
    int ret = 0;

    if (service_v->waypoint_addr != 0 && service_v->waypoint_port != 0) {
        BPF_LOG(
            DEBUG,
            SERVICE,
            "find waypoint addr=[%pI4h:%u]",
            &service_v->waypoint_addr,
            bpf_ntohs(service_v->waypoint_port));
        ret = waypoint_manager(ctx, service_v->waypoint_addr, service_v->waypoint_port);
        if (ret == -ENOEXEC) {
            BPF_LOG(ERR, BACKEND, "waypoint_manager failed, ret:%d\n", ret);
            return ret;
        }
    }

    BPF_LOG(DEBUG, SERVICE, "load balance type:%u", service_v->lb_policy);
    switch (service_v->lb_policy) {
    case LB_POLICY_RANDOM:
        ret = lb_random_handle(ctx, service_id, service_v);
        break;
    defalut:
        BPF_LOG(ERR, SERVICE, "unsupport load balance type:%u\n", service_v->lb_policy);
        ret = -EINVAL;
        break;
    }

    return ret;
}

#endif
