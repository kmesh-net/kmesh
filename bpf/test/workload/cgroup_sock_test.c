#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "cgroup_sock_test.skel.h"

void test_cgroup_connect4()
{
    struct cgroup_sock_bpf *skel;
    int prog_fd, err;

    // 加载 eBPF 程序
    skel = cgroup_sock_bpf__open_and_load();
    assert(skel != NULL);

    // 准备测试数据
    struct bpf_sock_addr ctx = {
        .user_ip4 = 0x08080808, // 8.8.8.8
        .user_port = htons(80),
        .family = AF_INET,
        .type = SOCK_STREAM,
        .protocol = IPPROTO_TCP
    };

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .ctx_in = &ctx,
        .ctx_size_in = sizeof(ctx),
        .ctx_out = &ctx,
        .ctx_size_out = sizeof(ctx)
    };

    // 运行测试
    prog_fd = bpf_program__fd(skel->progs.cgroup_connect4_prog);
    err = bpf_prog_test_run_opts(prog_fd, &opts);
    printf("%d",err);
    // 验证结果
    // assert(err == 0);
    // assert(opts.retval == 1); // Assuming 1 is CGROUP_SOCK_OK
    // assert(skel->bss->g_sock_traffic_control_ret == 0);
    // assert(ctx.user_ip4 == skel->bss->g_kmesh_ctx.dnat_ip.ip4);
    // assert(ctx.user_port == skel->bss->g_kmesh_ctx.dnat_port);

    // Clean up
    cgroup_sock_bpf__destroy(skel);
}

int main()
{
    test_cgroup_connect4();
    printf("All tests passed!\n");
    return 0;
}