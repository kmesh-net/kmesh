// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/tcp.h>
#include "bpf_log.h"
#include "ctx/sock_addr.h"
#include "frontend.h"
#include "bpf_common.h"

static inline int sock4_traffic_control(struct bpf_sock_addr *ctx)
{
    int ret;
    frontend_value *frontend_v = NULL;

    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    DECLARE_FRONTEND_KEY(ctx, frontend_k);

    DECLARE_VAR_IPV4(ctx->user_ip4, ip);
    BPF_LOG(DEBUG, KMESH, "origin addr=[%pI4h:%u]\n", &ip, bpf_ntohs(ctx->user_port));
    frontend_v = map_lookup_frontend(&frontend_k);
    if (!frontend_v) {
        return -ENOENT;
    }

    BPF_LOG(DEBUG, KMESH, "bpf find frontend addr=[%pI4h:%u]\n", &ip, bpf_ntohs(ctx->user_port));
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
    if (handle_kmesh_manage_process(ctx) || !is_kmesh_enabled(ctx)) {
        return CGROUP_SOCK_OK;
    }

    if (handle_bypass_process(ctx) || is_bypass_enabled(ctx)) {
        return CGROUP_SOCK_OK;
    }

    int ret = sock4_traffic_control(ctx);

    return CGROUP_SOCK_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;