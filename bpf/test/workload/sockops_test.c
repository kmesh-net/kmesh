// test_sockops.c
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <assert.h>
#include "sockops.skel.h"

// 辅助函数：重置全局变量
static void reset_globals(struct sockops_test_bpf *skel) {
    skel->bss->g_is_managed = 0;
    skel->bss->g_auth_called = 0;
    memset(&skel->bss->g_skops, 0, sizeof(skel->bss->g_skops));
    memset(&skel->bss->g_tuple_key, 0, sizeof(skel->bss->g_tuple_key));
    memset(&skel->bss->g_manager_key, 0, sizeof(skel->bss->g_manager_key));
    skel->bss->g_manager_value = 0;
    memset(&skel->bss->g_ringbuf_msg, 0, sizeof(skel->bss->g_ringbuf_msg));
    skel->bss->g_current_sk = 0;
    skel->bss->g_dst = NULL;
}

// 测试 IPv4 被动建立连接
static void test_ipv4_passive_established(struct sockops_test_bpf *skel) {
    int prog_fd, err;

    reset_globals(skel);

    // 设置测试数据
    skel->bss->g_skops.family = AF_INET;
    skel->bss->g_skops.local_ip4 = 0x0100007F;  // 127.0.0.1
    skel->bss->g_skops.remote_ip4 = 0x08080808; // 8.8.8.8
    skel->bss->g_skops.local_port = 12345;
    skel->bss->g_skops.remote_port = 80;
    skel->bss->g_skops.op = BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB;

    // 设置 map_of_manager
    struct manager_key key = {.addr.ip4 = 0x0100007F};
    __u32 value = 0;
    err = bpf_map__update_elem(skel->maps.map_of_manager, &key, sizeof(key), &value, sizeof(value), BPF_ANY);
    assert(err == 0);

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .ctx_in = &skel->bss->g_skops,
        .ctx_size_in = sizeof(skel->bss->g_skops),
        .ctx_out = &skel->bss->g_skops,
        .ctx_size_out = sizeof(skel->bss->g_skops)
    };

    // 运行测试
    prog_fd = bpf_program__fd(skel->progs.sockops_prog);
    err = bpf_prog_test_run_opts(prog_fd, &opts);

    // 验证结果
    assert(err == 0);
    assert(opts.retval == 0);
    assert(skel->bss->g_is_managed == 1);
    assert(skel->bss->g_auth_called == 1);
    assert(skel->bss->g_tuple_key.ipv4.saddr == 0x08080808); // 验证 tuple_key 被正确设置
    assert(skel->bss->g_tuple_key.ipv4.daddr == 0x0100007F);
    assert(skel->bss->g_ringbuf_msg.type == IPV4);

    printf("IPv4 passive established test passed\n");
}

// 测试 IPv6 主动建立连接
static void test_ipv6_active_established(struct sockops_test_bpf *skel) {
    int prog_fd, err;

    reset_globals(skel);

    // 设置测试数据
    skel->bss->g_skops.family = AF_INET6;
    // 设置 IPv6 地址 (::1 和 2001:4860:4860::8888)
    skel->bss->g_skops.local_ip6[3] = htonl(1);
    skel->bss->g_skops.remote_ip6[0] = htonl(0x20010486);
    skel->bss->g_skops.remote_ip6[1] = htonl(0x04860000);
    skel->bss->g_skops.remote_ip6[3] = htonl(0x8888);
    skel->bss->g_skops.local_port = 12345;
    skel->bss->g_skops.remote_port = 80;
    skel->bss->g_skops.op = BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB;

    // 设置 map_of_manager
    struct manager_key key = {0};
    key.addr.ip6[3] = htonl(1);
    __u32 value = 0;
    err = bpf_map__update_elem(skel->maps.map_of_manager, &key, sizeof(key), &value, sizeof(value), BPF_ANY);
    assert(err == 0);

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .ctx_in = &skel->bss->g_skops,
        .ctx_size_in = sizeof(skel->bss->g_skops),
        .ctx_out = &skel->bss->g_skops,
        .ctx_size_out = sizeof(skel->bss->g_skops)
    };

    // 运行测试
    prog_fd = bpf_program__fd(skel->progs.sockops_prog);
    err = bpf_prog_test_run_opts(prog_fd, &opts);

    // 验证结果
    assert(err == 0);
    assert(opts.retval == 0);
    assert(skel->bss->g_is_managed == 1);
    assert(skel->bss->g_auth_called == 0); // 主动连接不调用 auth_ip_tuple
    assert(skel->bss->g_tuple_key.ipv6.saddr[3] == htonl(1));
    assert(skel->bss->g_tuple_key.ipv6.daddr[0] == htonl(0x20010486));

    printf("IPv6 active established test passed\n");
}

// 测试连接关闭
static void test_connection_close(struct sockops_test_bpf *skel) {
    int prog_fd, err;

    reset_globals(skel);

    // 设置测试数据
    skel->bss->g_skops.family = AF_INET;
    skel->bss->g_skops.local_ip4 = 0x0100007F;  // 127.0.0.1
    skel->bss->g_skops.remote_ip4 = 0x08080808; // 8.8.8.8
    skel->bss->g_skops.op = BPF_SOCK_OPS_STATE_CB;
    skel->bss->g_skops.args[1] = BPF_TCP_CLOSE;

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .ctx_in = &skel->bss->g_skops,
        .ctx_size_in = sizeof(skel->bss->g_skops),
        .ctx_out = &skel->bss->g_skops,
        .ctx_size_out = sizeof(skel->bss->g_skops)
    };

    // 运行测试
    prog_fd = bpf_program__fd(skel->progs.sockops_prog);
    err = bpf_prog_test_run_opts(prog_fd, &opts);

    // 验证结果
    assert(err == 0);
    assert(opts.retval == 0);
    // 这里可以添加更多的断言来验证清理操作是否正确执行

    printf("Connection close test passed\n");
}

int main() {
    struct sockops_test_bpf *skel;

    // 加载 eBPF 程序
    skel = sockops_test_bpf__open_and_load();
    assert(skel != NULL);

    test_ipv4_passive_established(skel);
    test_ipv6_active_established(skel);
    test_connection_close(skel);

    // 清理
    sockops_test_bpf__destroy(skel);

    printf("All tests passed!\n");
    return 0;
}