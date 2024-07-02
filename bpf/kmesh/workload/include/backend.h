/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __ROUTE_BACKEND_H__
#define __ROUTE_BACKEND_H__

#include "workload_common.h"
#include "encoder.h"
#include "tail_call.h"

#define TAIL_CALL_CONNECT4_INDEX 0
#define TAIL_CALL_CONNECT6_INDEX 1

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
backend_manager(struct kmesh_context *kmesh_ctx, backend_value *backend_v, __u32 service_id, service_value *service_v)
{
    int ret;
    ctx_buff_t *ctx = (ctx_buff_t *)kmesh_ctx->ctx;
    __u32 user_port = ctx->user_port;

    if (backend_v->waypoint_port != 0) {
        BPF_LOG(
            DEBUG,
            BACKEND,
            "find waypoint addr=[%s:%u]\n",
            ip2str(&backend_v->wp_addr, ctx->family == AF_INET),
            bpf_ntohs(backend_v->waypoint_port));
        ret = waypoint_manager(kmesh_ctx, &backend_v->wp_addr, backend_v->waypoint_port);
        if (ret != 0) {
            BPF_LOG(ERR, BACKEND, "waypoint_manager failed, ret: %d\n", ret);
        }
        return ret;
    }

#pragma unroll
    for (__u32 i = 0; i < backend_v->service_count; i++) {
        if (i >= MAX_PORT_COUNT) {
            BPF_LOG(WARN, BACKEND, "exceed the max port count:%d", MAX_PORT_COUNT);
            return -EINVAL;
        }
        if (service_id == backend_v->service[i]) {
            BPF_LOG(DEBUG, BACKEND, "access the backend by service:%u\n", service_id);
#pragma unroll
            for (__u32 j = 0; j < MAX_PORT_COUNT; j++) {
                if (user_port == service_v->service_port[j]) {
                    if (ctx->user_family == AF_INET)
                        kmesh_ctx->dnat_ip.ip4 = backend_v->addr.ip4;
                    else
                        bpf_memcpy(kmesh_ctx->dnat_ip.ip6, backend_v->addr.ip6, IPV6_ADDR_LEN);
                    kmesh_ctx->dnat_port = service_v->target_port[j];
                    kmesh_ctx->via_waypoint = false;
                    BPF_LOG(
                        DEBUG,
                        BACKEND,
                        "get the backend addr=[%s:%u]\n",
                        ip2str(&kmesh_ctx->dnat_ip, ctx->family == AF_INET),
                        bpf_ntohs(service_v->target_port[j]));
                    return 0;
                }
            }
        }
    }

    BPF_LOG(ERR, BACKEND, "failed to get the backend\n");
    return -ENOENT;
}

#endif
