// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include "bpf_log.h"
#include "ctx/sock_addr.h"
#include "frontend.h"
#include "bpf_common.h"

static inline int sock4_traffic_control(struct kmesh_context *kmesh_ctx)
{
    int ret;
    frontend_value *frontend_v = NULL;
    struct bpf_sock_addr *ctx = kmesh_ctx->ctx;

    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    DECLARE_FRONTEND_KEY(ctx, &kmesh_ctx->orig_dst_addr, frontend_k);

    DECLARE_VAR_IPV4(ctx->user_ip4, ip);
    BPF_LOG(DEBUG, KMESH, "origin addr=[%s:%u]\n", ip2str(&ip, 1), bpf_ntohs(ctx->user_port));
    frontend_v = map_lookup_frontend(&frontend_k);
    if (!frontend_v) {
        return -ENOENT;
    }

    BPF_LOG(DEBUG, KMESH, "bpf find frontend addr=[%s:%u]\n", ip2str(&ip, 1), bpf_ntohs(ctx->user_port));
    ret = frontend_manager(ctx, frontend_v);
    if (ret != 0) {
        if (ret != -ENOENT)
            BPF_LOG(ERR, KMESH, "frontend_manager failed, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

SEC("cgroup/connect4")
int cgroup_connect4_prog(struct bpf_sock_addr *ctx)
{
    struct kmesh_context kmesh_ctx = {0};
    kmesh_ctx.ctx = ctx;
    kmesh_ctx.orig_dst_addr.ip4 = ctx->user_ip4;
    kmesh_ctx.dnat_ip.ip4 = ctx->user_ip4;
    kmesh_ctx.dnat_port = ctx->user_port;

    if (handle_kmesh_manage_process(ctx) || !is_kmesh_enabled(ctx)) {
        return CGROUP_SOCK_OK;
    }

    if (handle_bypass_process(ctx) || is_bypass_enabled(ctx)) {
        return CGROUP_SOCK_OK;
    }

    int ret = sock4_traffic_control(&kmesh_ctx);
    if (ret) {
        BPF_LOG(ERR, KMESH, "sock_traffic_control failed: %d\n", ret);
        return CGROUP_SOCK_OK;
    }

    SET_CTX_ADDRESS4(ctx, &kmesh_ctx.dnat_ip, kmesh_ctx.dnat_port);
    if (kmesh_ctx.via_waypoint) {
        kmesh_workload_tail_call(ctx, TAIL_CALL_CONNECT4_INDEX);

        // if tail call failed will run this code
        BPF_LOG(ERR, KMESH, "workload tail call failed, err is %d\n", ret);
    }
    return CGROUP_SOCK_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;