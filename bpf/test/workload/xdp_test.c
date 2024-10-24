// test_xdp.c
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include "xdp_test.skel.h"

void setup_ipv4_packet(struct xdp_test_bpf *skel)
{
    skel->bss->g_eth.h_proto = htons(ETH_P_IP);
    skel->bss->g_iph.version = 4;
    skel->bss->g_iph.ihl = 5;
    skel->bss->g_iph.protocol = IPPROTO_TCP;
    skel->bss->g_iph.saddr = inet_addr("192.168.1.100");
    skel->bss->g_iph.daddr = inet_addr("10.0.0.1");
    skel->bss->g_tcph.source = htons(12345);
    skel->bss->g_tcph.dest = htons(80);
}

void setup_ipv6_packet(struct xdp_test_bpf *skel)
{
    skel->bss->g_eth.h_proto = htons(ETH_P_IPV6);
    skel->bss->g_ip6h.version = 6;
    skel->bss->g_ip6h.nexthdr = IPPROTO_TCP;
    inet_pton(AF_INET6, "2001:db8::1", skel->bss->g_ip6h.saddr.in6_u.u6_addr8);
    inet_pton(AF_INET6, "2001:db8::2", skel->bss->g_ip6h.daddr.in6_u.u6_addr8);
    skel->bss->g_tcph.source = htons(12345);
    skel->bss->g_tcph.dest = htons(80);
}

void setup_auth_map(struct xdp_test_bpf *skel, bool is_ipv4)
{
    struct bpf_sock_tuple key = {0};
    __u32 value = 1;
    int err;

    if (is_ipv4) {
        key.ipv4.saddr = inet_addr("192.168.1.100");
        key.ipv4.daddr = inet_addr("10.0.0.1");
        key.ipv4.sport = htons(12345);
        key.ipv4.dport = htons(80);
    } else {
        inet_pton(AF_INET6, "2001:db8::1", key.ipv6.saddr);
        inet_pton(AF_INET6, "2001:db8::2", key.ipv6.daddr);
        key.ipv6.sport = htons(12345);
        key.ipv6.dport = htons(80);
    }

    err = bpf_map__update_elem(skel->maps.map_of_auth, &key, sizeof(key), &value, sizeof(value), BPF_ANY);
    assert(err == 0);
}

void run_xdp_test(struct xdp_test_bpf *skel, bool is_ipv4)
{
    int prog_fd, err;

    // 重置全局变量
    skel->bss->g_auth_result = 0;
    skel->bss->g_shutdown_called = 0;

    // 设置数据包
    if (is_ipv4) {
        setup_ipv4_packet(skel);
    } else {
        setup_ipv6_packet(skel);
    }

    // 设置认证映射
    setup_auth_map(skel, is_ipv4);

    // 设置 XDP 上下文
    skel->bss->g_ctx.data = (__u64)&skel->bss->g_eth;
    skel->bss->g_ctx.data_end = (__u64)(&skel->bss->g_tcph + 1);

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .ctx_in = &skel->bss->g_ctx,
        .ctx_size_in = sizeof(skel->bss->g_ctx),
        .ctx_out = &skel->bss->g_ctx,
        .ctx_size_out = sizeof(skel->bss->g_ctx)
    };

    // 运行测试
    prog_fd = bpf_program__fd(skel->progs.xdp_shutdown);
    err = bpf_prog_test_run_opts(prog_fd, &opts);

    // 验证结果
    assert(err == 0);
    assert(opts.retval == XDP_PASS);
    assert(skel->bss->g_auth_result == 1);
    assert(skel->bss->g_shutdown_called == 1);
    assert(skel->bss->g_tcph.rst == 1);

    printf("%s XDP test passed\n", is_ipv4 ? "IPv4" : "IPv6");
}

int main()
{
    struct xdp_test_bpf *skel;

    // 加载 eBPF 程序
    skel = xdp_test_bpf__open_and_load();
    assert(skel != NULL);

    run_xdp_test(skel, true);  // IPv4 test
    run_xdp_test(skel, false); // IPv6 test

    // 清理
    xdp_test_bpf__destroy(skel);

    printf("All tests passed!\n");
    return 0;
}