#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_log.h"
#include "bpf_common.h"


SEC("cgroup/connect4") 
int cgroup_connect4_tail(struct bpf_sock_addr *ctx)
{
    BPF_LOG(INFO, KMESH, ">> Tail called into cgroup_connect_tail!\n");
    return 1;
}
SEC("cgroup/connect6") 
int cgroup_connect6_tail(struct bpf_sock_addr *ctx)
{
    BPF_LOG(INFO, KMESH, ">> Tail called into cgroup_connect_tail!\n");
    return 1;
}
#include "workload/cgroup_sock.c"
