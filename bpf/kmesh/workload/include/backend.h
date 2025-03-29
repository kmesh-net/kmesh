/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __ROUTE_BACKEND_H__
#define __ROUTE_BACKEND_H__

#include "workload_common.h"
#include "tail_call.h"

static inline backend_value *map_lookup_backend(const backend_key *key)
{
    return kmesh_map_lookup_elem(&map_of_backend, key);
}

static inline int waypoint_manager(struct kmesh_context *kmesh_ctx, struct ip_addr *wp_addr, __u32 port)
{
    ctx_buff_t *ctx = (ctx_buff_t *)kmesh_ctx->ctx;

    if (ctx->user_family == AF_INET)
        kmesh_ctx->dnat_ip.ip4 = wp_addr->ip4;
    else
        bpf_memcpy(kmesh_ctx->dnat_ip.ip6, wp_addr->ip6, IPV6_ADDR_LEN);
    kmesh_ctx->dnat_port = port;
    kmesh_ctx->via_waypoint = true;
    return 0;
}

static inline int svc_dnat(struct kmesh_context *kmesh_ctx, backend_value *backend_v, service_value *service_v)
{
    int i;
    ctx_buff_t *ctx = (ctx_buff_t *)kmesh_ctx->ctx;

#pragma unroll
    for (i = 0; i < MAX_PORT_COUNT; i++) {
        if (ctx->user_port == service_v->service_port[i]) {
            if (ctx->user_family == AF_INET)
                kmesh_ctx->dnat_ip.ip4 = backend_v->addr.ip4;
            else
                bpf_memcpy(kmesh_ctx->dnat_ip.ip6, backend_v->addr.ip6, IPV6_ADDR_LEN);

            kmesh_ctx->dnat_port = service_v->target_port[i];
            kmesh_ctx->via_waypoint = false;
            return 0;
        }
    }

    BPF_LOG(
        ERR,
        BACKEND,
        "svc_dnat: cannot find matched service port [%s:%u]\n",
        ip2str((__u32 *)&backend_v->addr.ip6, ctx->family == AF_INET),
        bpf_ntohs(ctx->user_port));
    return -ENOENT;
}

static inline int
backend_manager(struct kmesh_context *kmesh_ctx, backend_value *backend_v, __u32 service_id, service_value *service_v)
{
    int ret = -ENOENT;
    ctx_buff_t *ctx = (ctx_buff_t *)kmesh_ctx->ctx;
    __u32 i, user_port = ctx->user_port;

    if (backend_v->waypoint_port != 0) {
        BPF_LOG(
            DEBUG,
            BACKEND,
            "route to waypoint[%s:%u]\n",
            ip2str((__u32 *)&backend_v->wp_addr, ctx->family == AF_INET),
            bpf_ntohs(backend_v->waypoint_port));
        ret = waypoint_manager(kmesh_ctx, &backend_v->wp_addr, backend_v->waypoint_port);
        return ret;
    }

    ret = svc_dnat(kmesh_ctx, backend_v, service_v);
    if (ret == 0) {
        BPF_LOG(
            DEBUG,
            BACKEND,
            "svc %u dnat to [%s:%u]\n",
            service_id,
            ip2str((__u32 *)&kmesh_ctx->dnat_ip, ctx->family == AF_INET),
            bpf_ntohs(kmesh_ctx->dnat_port));
    }

    return ret;
}

#endif
