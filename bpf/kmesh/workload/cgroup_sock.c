// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <sys/socket.h>
#include "bpf_log.h"
#include "ctx/sock_addr.h"
#include "frontend.h"
#include "bpf_common.h"
#include "probe.h"
#include "encoder.h"
#include "tcp_probe.h"

#define TIMER_INTERVAL_NS 1000000000 // 1 seconds (in nanoseconds)

// BPF Timer map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, __u64);
} tcp_conn_last_flush SEC(".maps");

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
    int ret;
    struct bpf_sock_tuple sk_tuple = {0};
    ctx_buff_t *ctx = (ctx_buff_t *)kmesh_ctx->ctx;
    __u64 *sk = (__u64 *)ctx->sk;

    if (kmesh_ctx->via_waypoint) {
        // since this field is never used, we use it
        // to indicate whether the request will be handled by waypoint
        sk_tuple.ipv4.saddr = 1;
    }

    if (ctx->family == AF_INET) {
        sk_tuple.ipv4.daddr = kmesh_ctx->orig_dst_addr.ip4;
        sk_tuple.ipv4.dport = ctx->user_port;
    } else if (ctx->family == AF_INET6) {
        bpf_memcpy(sk_tuple.ipv6.daddr, kmesh_ctx->orig_dst_addr.ip6, IPV6_ADDR_LEN);
        sk_tuple.ipv6.dport = ctx->user_port;
    }

    ret = bpf_map_update_elem(&map_of_orig_dst, &(sk), &sk_tuple, BPF_NOEXIST);
    if (ret) {
        // only record the first dst info for each socket
        if (ret == -EEXIST)
            return 0;
        BPF_LOG(ERR, BACKEND, "record original dst address failed: %d\n", ret);
        return ret;
    }
    return 0;
}

static inline bool is_managed_by_kmesh(struct __sk_buff *skb)
{
    struct manager_key key = {0};

    if (skb->family == AF_INET)
        key.addr.ip4 = skb->local_ip4;
    if (skb->family == AF_INET6) {
        if (is_ipv4_mapped_addr(skb->local_ip6))
            key.addr.ip4 = skb->local_ip6[3];
        else
            IP6_COPY(key.addr.ip6, skb->local_ip6);
    }

    int *value = bpf_map_lookup_elem(&map_of_manager, &key);
    if (!value)
        return false;
    return (*value == 0);
}

static inline void flush_tcp_conns()
{
    struct __u64 *key = NULL, *next_key = NULL;
    struct tcp_probe_info *conn;

    __u32 zero = 0;
    __u32 *max_index = bpf_map_lookup_elem(&map_of_soc_id_counter, &zero);
    if (!max_index || *max_index == 0)
        return;

    for (__u32 i = 0; i < *max_index && i < MAP_SIZE_OF_TCP_CONNS; i++) {
        __u64 *key = bpf_map_lookup_elem(&map_of_soc_id, &i);

        if (!key)
            break;

        conn = bpf_map_lookup_elem(&map_of_tcp_conns, key);
        if (!conn) {
            for (__u32 j = i; j < *max_index - 1 && j < MAP_SIZE_OF_TCP_CONNS - 1; j++) {
                __u64 *next_key = bpf_map_lookup_elem(&map_of_soc_id, &j + 1);
                if (next_key) {
                    bpf_map_update_elem(&map_of_soc_id, &j, next_key, BPF_ANY);
                }
            }

            // Clear the last entry
            __u32 m_index = *max_index - 1;
            bpf_map_update_elem(&map_of_soc_id, &m_index, &zero, BPF_ANY);

            // Decrement the counter
            *max_index -= 1;
            continue;
        }
        __u64 now = bpf_ktime_get_ns();
        // Check if connection duration exceeds threshold
        if ((now - conn->start_ns) > LONG_CONN_THRESHOLD_TIME) {
            report_after_threshold_tm(conn);
        }
    }
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

SEC("cgroup/skb")
int cgroup_skb_prog(struct __sk_buff *skb)
{
    if (!is_managed_by_kmesh(skb))
        return 0;

    struct bpf_sock *sk = skb->sk;
    if (!sk) {
        BPF_LOG(ERR, TC, "Failed to get tcp sock\n");
        return 0;
    }

    observe_on_data(sk);

    int key = 0;
    __u64 *last_time = bpf_map_lookup_elem(&tcp_conn_last_flush, &key);
    __u64 now = bpf_ktime_get_ns();

    if (!last_time) {
        __u64 init_time = now;
        // Initialize last flush time if not set
        bpf_map_update_elem(&tcp_conn_last_flush, &key, &init_time, BPF_ANY);
    } else if ((now - *last_time) >= TIMER_INTERVAL_NS) {
        flush_tcp_conns();
        // Update last flush time
        bpf_map_update_elem(&tcp_conn_last_flush, &key, &now, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;
