// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include "config.h"
#include "bpf_log.h"
#include "workload.h"

#define AUTH_PASS   0
#define AUTH_FORBID 1

#define PARSER_FAILED 1
#define PARSER_SUCC   0

struct xdp_info {
    struct ethhdr *ethh;
    union {
        struct iphdr *iph;
        struct ipv6hdr *ip6h;
    };
    struct tcphdr *tcph;
};

// 全局变量，用于测试
struct xdp_md g_ctx = {0};
struct ethhdr g_eth = {0};
struct iphdr g_iph = {0};
struct ipv6hdr g_ip6h = {0};
struct tcphdr g_tcph = {0};
struct bpf_sock_tuple g_tuple = {0};
__u32 g_auth_result = 0;
__u32 g_shutdown_called = 0;

// 新增全局变量，用于测试各个函数
struct xdp_info g_xdp_info = {0};
__u32 g_parser_tuple_called = 0;
__u32 g_should_shutdown_result = 0;
__u32 g_parser_xdp_info_result = 0;

static inline void parser_tuple(struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    // 标记函数被调用
    g_parser_tuple_called = 1;

    // 使用全局变量替代传入的参数
    if (g_iph.version == 4) {
        g_tuple.ipv4.saddr = g_iph.saddr;
        g_tuple.ipv4.daddr = g_iph.daddr;
        g_tuple.ipv4.sport = g_tcph.source;
        g_tuple.ipv4.dport = g_tcph.dest;
    } else {
        bpf_memcpy((__u8 *)g_tuple.ipv6.saddr, g_ip6h.saddr.in6_u.u6_addr8, IPV6_ADDR_LEN);
        bpf_memcpy((__u8 *)g_tuple.ipv6.daddr, g_ip6h.daddr.in6_u.u6_addr8, IPV6_ADDR_LEN);
        g_tuple.ipv6.sport = g_tcph.source;
        g_tuple.ipv6.dport = g_tcph.dest;
    }
}

static inline void shutdown_tuple(struct xdp_info *info)
{
    // 使用全局变量替代传入的参数
    g_tcph.fin = 0;
    g_tcph.syn = 0;
    g_tcph.rst = 1;
    g_tcph.psh = 0;
    g_tcph.ack = 0;
    // 设置全局变量，表示 shutdown_tuple 被调用
    g_shutdown_called = 1;
}

static inline int should_shutdown(struct xdp_info *info, struct bpf_sock_tuple *tuple_info)
{
    // 模拟 bpf_map_lookup_elem 的行为
    __u32 *value = (__u32 *)&g_auth_result;
    if (value && *value) {
        if (g_iph.version == 4)
            BPF_LOG(
                INFO,
                XDP,
                "auth denied, src ip: %s, port: %u\n",
                ip2str(&g_tuple.ipv4.saddr, true),
                bpf_ntohs(g_tuple.ipv4.sport));
        else
            BPF_LOG(
                INFO,
                XDP,
                "auth denied, src ip: %s, port: %u\n",
                ip2str(&g_tuple.ipv6.saddr[0], false),
                bpf_ntohs(g_tuple.ipv6.sport));
        // 模拟 bpf_map_delete_elem 的行为
        g_auth_result = 0;
        g_should_shutdown_result = AUTH_FORBID;
        return AUTH_FORBID;
    }
    g_should_shutdown_result = AUTH_PASS;
    return AUTH_PASS;
}

static inline int parser_xdp_info(struct xdp_md *ctx, struct xdp_info *info)
{
    // 使用全局变量替代传入的参数
    g_xdp_info.ethh = &g_eth;
    g_xdp_info.iph = &g_iph;
    g_xdp_info.ip6h = &g_ip6h;
    g_xdp_info.tcph = &g_tcph;

    // 简化解析逻辑，直接使用全局变量
    if (g_iph.version != 4 && g_iph.version != 6) {
        g_parser_xdp_info_result = PARSER_FAILED;
        return PARSER_FAILED;
    }

    if (g_iph.version == 4 && g_iph.protocol != IPPROTO_TCP) {
        g_parser_xdp_info_result = PARSER_FAILED;
        return PARSER_FAILED;
    }

    if (g_iph.version == 6 && g_ip6h.nexthdr != IPPROTO_TCP) {
        g_parser_xdp_info_result = PARSER_FAILED;
        return PARSER_FAILED;
    }

    g_parser_xdp_info_result = PARSER_SUCC;
    return PARSER_SUCC;
}

SEC("xdp_auth")
int xdp_shutdown(struct xdp_md *ctx)
{
    struct xdp_info info = {0};
    struct bpf_sock_tuple tuple_info = {0};

    // 使用全局变量 g_ctx 替代 ctx，方便测试
    if (parser_xdp_info(&g_ctx, &info) == PARSER_FAILED)
        return XDP_PASS;
    if (g_iph.version != 4 && g_iph.version != 6)
        return XDP_PASS;

    parser_tuple(&info, &tuple_info);
    if (should_shutdown(&info, &tuple_info) == AUTH_FORBID)
        shutdown_tuple(&info);

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;