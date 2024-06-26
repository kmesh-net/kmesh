// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/tcp.h>
#include "bpf_log.h"
#include "ctx/sock_addr.h"
#include "listener.h"
#include "listener/listener.pb-c.h"
#include "filter.h"
#include "cluster.h"
#include "bpf_common.h"

#if KMESH_ENABLE_IPV4
#if KMESH_ENABLE_HTTP

static const char kmesh_module_name[] = "kmesh_defer";

static inline int sock4_traffic_control(struct bpf_sock_addr *ctx)
{
    int ret;

    Listener__Listener *listener = NULL;

    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    DECLARE_VAR_ADDRESS(ctx, address);

    listener = map_lookup_listener(&address);
    if (listener == NULL) {
        address.ipv4 = 0;
        listener = map_lookup_listener(&address);
        if (!listener)
            return -ENOENT;
    }
    DECLARE_VAR_IPV4(ctx->user_ip4, ip);
    BPF_LOG(DEBUG, KMESH, "bpf find listener addr=[%s:%u]\n", ip2str(&ip, 1), bpf_ntohs(ctx->user_port));

#if ENHANCED_KERNEL
    // todo build when kernel support http parse and route
    // defer conn
    ret = bpf_setsockopt(ctx, IPPROTO_TCP, TCP_ULP, (void *)kmesh_module_name, sizeof(kmesh_module_name));
    if (ret)
        BPF_LOG(ERR, KMESH, "bpf set sockopt failed! ret:%d\n", ret);
#else  // KMESH_ENABLE_HTTP
    ret = listener_manager(ctx, listener, NULL);
    if (ret != 0) {
        BPF_LOG(ERR, KMESH, "listener_manager failed, ret %d\n", ret);
        return ret;
    }
#endif // KMESH_ENABLE_HTTP

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

    if (handle_kmesh_manage_process(&kmesh_ctx) || !is_kmesh_enabled(ctx)) {
        return CGROUP_SOCK_OK;
    }
    if (handle_bypass_process(&kmesh_ctx) || is_bypass_enabled(ctx)) {
        return CGROUP_SOCK_OK;
    }
    int ret = sock4_traffic_control(ctx);
    return CGROUP_SOCK_OK;
}

#endif // KMESH_ENABLE_TCP
#endif // KMESH_ENABLE_IPV4

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;
