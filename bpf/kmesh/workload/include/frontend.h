/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __KMESH_FRONTEND_H__
#define __KMESH_FRONTEND_H__

#include "workload_common.h"
#include "service.h"
#include "backend.h"

static inline frontend_value *map_lookup_frontend(const frontend_key *key)
{
    return kmesh_map_lookup_elem(&map_of_frontend, key);
}

static inline int frontend_manager(struct kmesh_context *kmesh_ctx, frontend_value *frontend_v)
{
    int ret = 0;
    service_key service_k = {0};
    service_value *service_v = NULL;
    backend_key backend_k = {0};
    backend_value *backend_v = NULL;
    bool direct_backend = false;

    service_k.service_id = frontend_v->upstream_id;
    service_v = map_lookup_service(&service_k);
    if (!service_v) {
        backend_k.backend_uid = frontend_v->upstream_id;
        backend_v = map_lookup_backend(&backend_k);
        if (!backend_v) {
            BPF_LOG(WARN, FRONTEND, "find backend failed\n");
            return -ENOENT;
        }
        direct_backend = true;
    }

    if (direct_backend) {
        // For pod direct access, if a pod has watpoint captured, we will redirect to waypoint, otherwise we do nothing.
        if (backend_v->waypoint_port != 0) {
            BPF_LOG(
                DEBUG,
                FRONTEND,
                "find waypoint addr=[%s:%u]\n",
                ip2str(&backend_v->wp_addr, kmesh_ctx->ctx->family == AF_INET),
                bpf_ntohs(backend_v->waypoint_port));
            ret = waypoint_manager(kmesh_ctx, &backend_v->wp_addr, backend_v->waypoint_port);
            if (ret != 0) {
                BPF_LOG(ERR, BACKEND, "waypoint_manager failed, ret:%d\n", ret);
            }
            return ret;
        }
    } else {
        ret = service_manager(kmesh_ctx, frontend_v->upstream_id, service_v);
        if (ret != 0) {
            if (ret != -ENOENT)
                BPF_LOG(ERR, FRONTEND, "service_manager failed, ret:%d\n", ret);
            return ret;
        }
    }

    return 0;
}

#endif
