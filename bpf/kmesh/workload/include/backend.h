/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __ROUTE_BACKEND_H__
#define __ROUTE_BACKEND_H__

#include "workload_common.h"
#include "encoder.h"
#include "tail_call.h"

static inline backend_value *map_lookup_backend(const backend_key *key)
{
    return kmesh_map_lookup_elem(&map_of_backend, key);
}

static inline int waypoint_manager(struct kmesh_context *kmesh_ctx, struct ip_addr *wp_addr, __u32 port)
{
    int ret;
    address_t target_addr;
    ctx_buff_t *ctx = (ctx_buff_t *)kmesh_ctx->ctx;
    __u64 *sk = (__u64 *)ctx->sk;
    struct bpf_sock_tuple value_tuple = {0};

    if (ctx->family == AF_INET) {
        value_tuple.ipv4.daddr = kmesh_ctx->orig_dst_addr.ip4;
        value_tuple.ipv4.dport = ctx->user_port;
    } else if (ctx->family == AF_INET6) {
        bpf_memcpy(value_tuple.ipv6.daddr, kmesh_ctx->orig_dst_addr.ip6, IPV6_ADDR_LEN);
        value_tuple.ipv6.dport = ctx->user_port;
    } else {
        BPF_LOG(ERR, BACKEND, "invalid ctx family: %u\n", ctx->family);
        return -1;
    }
    ret = bpf_map_update_elem(&map_of_dst_info, &(sk), &value_tuple, BPF_NOEXIST);
    if (ret) {
        BPF_LOG(ERR, BACKEND, "record metadata origin address and port failed, ret is %d\n", ret);
        return ret;
    }

    if (ctx->user_family == AF_INET)
        kmesh_ctx->dnat_ip.ip4 = wp_addr->ip4;
    else
        bpf_memcpy(kmesh_ctx->dnat_ip.ip6, wp_addr->ip6, IPV6_ADDR_LEN);
    kmesh_ctx->dnat_port = port;
    kmesh_ctx->via_waypoint = true;
    return 0;
}

static inline int
update_dst_addr_with_service_port(struct kmesh_context *kmesh_ctx, backend_value *backend_v, service_value *service_v)
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
            "find waypoint addr=[%s:%u]\n",
            ip2str((__u32 *)&backend_v->wp_addr, ctx->family == AF_INET),
            bpf_ntohs(backend_v->waypoint_port));
        ret = waypoint_manager(kmesh_ctx, &backend_v->wp_addr, backend_v->waypoint_port);
        if (ret != 0) {
            BPF_LOG(ERR, BACKEND, "waypoint_manager failed, ret: %d\n", ret);
        }
        return ret;
    }

    ret = update_dst_addr_with_service_port(kmesh_ctx, backend_v, service_v);
    if (ret != 0)
        BPF_LOG(ERR, BACKEND, "cannot find matched service port [%d:%d]\n", service_id, kmesh_ctx->ctx->user_port);
    return ret;
}

#endif
