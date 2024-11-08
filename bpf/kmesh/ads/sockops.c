// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <sys/socket.h>
#include "bpf_log.h"
#include "ctx/sock_ops.h"
#include "listener.h"
#include "listener/listener.pb-c.h"
#include "filter.h"
#include "route_config.h"
#include "cluster.h"
#include "circuit_breaker.h"

#if KMESH_ENABLE_IPV4
#if KMESH_ENABLE_HTTP

static int sockops_traffic_control(struct bpf_sock_ops *skops, struct bpf_mem_ptr *msg)
{
    int ret;
    /* 1 lookup listener */
    DECLARE_VAR_ADDRESS(skops, addr);
    addr.port = GET_SKOPS_REMOTE_PORT(skops);

    Listener__Listener *listener = map_lookup_listener(&addr);

    if (!listener) {
        addr.ipv4 = 0;
        listener = map_lookup_listener(&addr);
        if (!listener) {
            /* no match vip/nodeport listener */
            return 0;
        }
    }

    DECLARE_VAR_IPV4(skops->remote_ip4, ip)
    BPF_LOG(
        DEBUG,
        SOCKOPS,
        "sockops_traffic_control listener=\"%s\", addr=[%s:%u]\n",
        (char *)KMESH_GET_PTR_VAL(listener->name, char *),
        ip2str(&ip, 1),
        bpf_ntohs(skops->remote_port));
    return listener_manager(skops, listener, msg);
}

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *skops)
{
#define BPF_CONSTRUCT_PTR(low_32, high_32) (unsigned long long)(((unsigned long long)(high_32) << 32) + (low_32))
    struct bpf_mem_ptr *msg = NULL;

    if (skops->family != AF_INET)
        return BPF_OK;

    switch (skops->op) {
    case BPF_SOCK_OPS_TCP_DEFER_CONNECT_CB:
        msg = (struct bpf_mem_ptr *)BPF_CONSTRUCT_PTR(skops->args[0], skops->args[1]);
        (void)sockops_traffic_control(skops, msg);
        break;
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
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
