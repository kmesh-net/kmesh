// test_sendmsg.c
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <assert.h>
#include "sendmsg_test.skel.h"


void test_sendmsg_ipv4()
{
    struct sendmsg_test_bpf *skel;
    int prog_fd, err;

    // 加载 eBPF 程序
    skel = sendmsg_test_bpf__open_and_load();
    assert(skel != NULL);

    // 准备测试数据
    skel->bss->g_msg.family = AF_INET;
    skel->bss->g_msg.sk = (__u64)12345; // 模拟 socket 指针

    skel->bss->g_dst_info.ipv4.daddr = 0x08080808; // 8.8.8.8
    skel->bss->g_dst_info.ipv4.dport = htons(80);

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .ctx_in = &skel->bss->g_msg,
        .ctx_size_in = sizeof(skel->bss->g_msg),
        .ctx_out = &skel->bss->g_msg,
        .ctx_size_out = sizeof(skel->bss->g_msg)
    };

    // 运行测试
    prog_fd = bpf_program__fd(skel->progs.sendmsg_prog);
    err = bpf_prog_test_run_opts(prog_fd, &opts);

    // 验证结果
    assert(err == 0);
    assert(opts.retval == SK_PASS);
    assert(skel->bss->g_encoded_length == TLV_ORG_DST_ADDR4_SIZE + TLV_END_SIZE);

    // 清理
    sendmsg_test_bpf__destroy(skel);
}

void test_sendmsg_ipv6()
{
    struct sendmsg_test_bpf *skel;
    int prog_fd, err;

    // 加载 eBPF 程序
    skel = sendmsg_test_bpf__open_and_load();
    assert(skel != NULL);

    // 准备测试数据
    skel->bss->g_msg.family = AF_INET6;
    skel->bss->g_msg.sk = (__u64)12345; // 模拟 socket 指针

    // 设置 IPv6 地址 (2001:4860:4860::8888)
    skel->bss->g_dst_info.ipv6.daddr[0] = htonl(0x20010486);
    skel->bss->g_dst_info.ipv6.daddr[1] = htonl(0x04860000);
    skel->bss->g_dst_info.ipv6.daddr[2] = 0;
    skel->bss->g_dst_info.ipv6.daddr[3] = htonl(0x8888);
    skel->bss->g_dst_info.ipv6.dport = htons(80);

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .ctx_in = &skel->bss->g_msg,
        .ctx_size_in = sizeof(skel->bss->g_msg),
        .ctx_out = &skel->bss->g_msg,
        .ctx_size_out = sizeof(skel->bss->g_msg)
    };

    // 运行测试
    prog_fd = bpf_program__fd(skel->progs.sendmsg_prog);
    err = bpf_prog_test_run_opts(prog_fd, &opts);

    // 验证结果
    assert(err == 0);
    assert(opts.retval == SK_PASS);
    assert(skel->bss->g_encoded_length == TLV_ORG_DST_ADDR6_SIZE + TLV_END_SIZE);

    // 清理
    sendmsg_test_bpf__destroy(skel);
}

int main()
{
    test_sendmsg_ipv4();
    test_sendmsg_ipv6();
    printf("All tests passed!\n");
    return 0;
}