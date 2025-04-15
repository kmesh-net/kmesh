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
#include "probe.h"

static inline int sock_traffic_control(struct kmesh_context *kmesh_ctx)
{
    observe_on_operation_start(SOCK_TRAFFIC_CONTROL, kmesh_ctx);
    int ret;
    frontend_value *frontend_v = NULL;
    frontend_key frontend_k = {0};
    struct bpf_sock_addr *ctx = kmesh_ctx->ctx;
    struct ip_addr orig_dst_addr = {0};

    if (ctx->family == AF_INET) {
        orig_dst_addr.ip4 = kmesh_ctx->orig_dst_addr.ip4;
        frontend_k.addr.ip4 = orig_dst_addr.ip4;
    } else if (ctx->family == AF_INET6) {
        IP6_COPY(orig_dst_addr.ip6, kmesh_ctx->orig_dst_addr.ip6);
        // Java applications use IPv6 for communication. In the IPv4 network environment, the control plane delivers the
        // IPv4 address to the bpf map but obtains the IPv4 mapped address from the bpf prog context. Therefore, address
        // translation is required before and after traffic manager.
        if (is_ipv4_mapped_addr(orig_dst_addr.ip6))
            V4_MAPPED_REVERSE(orig_dst_addr.ip6);
        bpf_memcpy(frontend_k.addr.ip6, orig_dst_addr.ip6, IPV6_ADDR_LEN);
    }

    BPF_LOG(
        DEBUG,
        KMESH,
        "origin dst addr=[%u:%s:%u]\n",
        ctx->family,
        ip2str((__u32 *)&kmesh_ctx->orig_dst_addr, (ctx->family == AF_INET)),
        bpf_ntohs(ctx->user_port));

    frontend_v = map_lookup_frontend(&frontend_k);
    if (!frontend_v) {
        return -ENOENT;
    }

    ret = frontend_manager(kmesh_ctx, frontend_v);
    if (ret != 0) {
        if (ret != -ENOENT)
            BPF_LOG(ERR, KMESH, "frontend_manager failed, ret:%d\n", ret);
        return ret;
    }
    observe_on_operation_end(SOCK_TRAFFIC_CONTROL, kmesh_ctx);
    return 0;
}

static inline int set_original_dst_info(struct kmesh_context *kmesh_ctx)
{
    struct bpf_sock *sk = (struct bpf_sock *)kmesh_ctx->ctx->sk;
    ctx_buff_t *ctx = (ctx_buff_t *)kmesh_ctx->ctx;

    struct sock_storage_data *storage = NULL;
    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!storage) {
        BPF_LOG(ERR, KMESH, "failed to get storage from map_of_sock_storage");
        return 0;
    }

    if (kmesh_ctx->via_waypoint) {
        storage->via_waypoint = true;
    }

    if (ctx->family == AF_INET && !storage->has_set_ip) {
        storage->sk_tuple.ipv4.daddr = kmesh_ctx->orig_dst_addr.ip4;
        storage->sk_tuple.ipv4.dport = ctx->user_port;
        storage->has_set_ip = true;
    } else if (ctx->family == AF_INET6 && !storage->has_set_ip) {
        bpf_memcpy(storage->sk_tuple.ipv6.daddr, kmesh_ctx->orig_dst_addr.ip6, IPV6_ADDR_LEN);
        storage->sk_tuple.ipv6.dport = ctx->user_port;
        storage->has_set_ip = true;
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

    if (handle_kmesh_manage_process(&kmesh_ctx) || !is_kmesh_enabled(ctx)) {
        return CGROUP_SOCK_OK;
    }

    if (ctx->protocol != IPPROTO_TCP)
        return CGROUP_SOCK_OK;

    observe_on_pre_connect(ctx->sk);

    int ret = sock_traffic_control(&kmesh_ctx);
    if (ret) {
        return CGROUP_SOCK_OK;
    }
    ret = set_original_dst_info(&kmesh_ctx);
    if (ret) {
        BPF_LOG(ERR, KMESH, "[IPv4]failed to set original destination info, ret is %d\n", ret);
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

SEC("cgroup/connect6")
int cgroup_connect6_prog(struct bpf_sock_addr *ctx)
{
    struct kmesh_context kmesh_ctx = {0};
    kmesh_ctx.ctx = ctx;
    IP6_COPY(kmesh_ctx.orig_dst_addr.ip6, ctx->user_ip6);
    IP6_COPY(kmesh_ctx.dnat_ip.ip6, kmesh_ctx.orig_dst_addr.ip6);
    kmesh_ctx.dnat_port = ctx->user_port;

    if (handle_kmesh_manage_process(&kmesh_ctx) || !is_kmesh_enabled(ctx)) {
        return CGROUP_SOCK_OK;
    }

    BPF_LOG(DEBUG, KMESH, "enter cgroup/connect6\n");
    if (ctx->protocol != IPPROTO_TCP)
        return CGROUP_SOCK_OK;

    observe_on_pre_connect(ctx->sk);

    int ret = sock_traffic_control(&kmesh_ctx);
    if (ret) {
        return CGROUP_SOCK_OK;
    }

    ret = set_original_dst_info(&kmesh_ctx);
    if (ret) {
        BPF_LOG(ERR, KMESH, "[IPv6]failed to set original destination info, ret is %d\n", ret);
        return CGROUP_SOCK_OK;
    }

    if (is_ipv4_mapped_addr(ctx->user_ip6) && !is_ipv4_mapped_addr(kmesh_ctx.dnat_ip.ip6))
        V4_MAPPED_TO_V6(kmesh_ctx.dnat_ip.ip4, kmesh_ctx.dnat_ip.ip6);
    SET_CTX_ADDRESS6(ctx, &kmesh_ctx.dnat_ip, kmesh_ctx.dnat_port);

    if (kmesh_ctx.via_waypoint) {
        kmesh_workload_tail_call(ctx, TAIL_CALL_CONNECT6_INDEX);

        // if tail call failed will run this code
        BPF_LOG(ERR, KMESH, "workload tail call6 failed, err is %d\n", ret);
    }

    return CGROUP_SOCK_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;
