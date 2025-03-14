// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <sys/socket.h>
#include "bpf_log.h"
#include "ctx/sock_ops.h"
#include "circuit_breaker.h"

#if KMESH_ENABLE_IPV4
#if KMESH_ENABLE_HTTP

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *skops)
{
#define BPF_CONSTRUCT_PTR(low_32, high_32) (unsigned long long)(((unsigned long long)(high_32) << 32) + (low_32))
    struct bpf_mem_ptr *msg = NULL;

    if (skops->family != AF_INET)
        return BPF_OK;

    switch (skops->op) {
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
        skops_handle_kmesh_managed_process(skops);
        break;
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        if (!is_managed_by_kmesh(skops))
            break;

        if (bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG) != 0) {
            BPF_LOG(ERR, SOCKOPS, "set sockops cb failed!\n");
        } else {
            on_cluster_sock_connect(skops);
        }
        break;
    case BPF_SOCK_OPS_STATE_CB:
        if (skops->args[1] == BPF_TCP_CLOSE) {
            on_cluster_sock_close(skops);
        }
        break;
    }
    return BPF_OK;
}

#endif
#endif
char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;