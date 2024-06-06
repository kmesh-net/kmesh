/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __KMESH_ENDPOINT_H__
#define __KMESH_ENDPOINT_H__

#include "workload_common.h"
#include "backend.h"

static inline endpoint_value *map_lookup_endpoint(const endpoint_key *key)
{
    return kmesh_map_lookup_elem(&map_of_endpoint, key);
}

static inline int
endpoint_manager(ctx_buff_t *ctx, endpoint_value *endpoint_v, __u32 service_id, service_value *service_v)
{
    int ret = 0;
    backend_key backend_k = {0};
    backend_value *backend_v = NULL;

    backend_k.backend_uid = endpoint_v->backend_uid;
    backend_v = map_lookup_backend(&backend_k);
    if (!backend_v) {
        BPF_LOG(WARN, ENDPOINT, "find backend %u failed", backend_k.backend_uid);
        return -ENOENT;
    }

    ret = backend_manager(ctx, backend_v, service_id, service_v);
    if (ret != 0) {
        if (ret != -ENOENT)
            BPF_LOG(ERR, ENDPOINT, "backend_manager failed, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

#endif
