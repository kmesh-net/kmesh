/*
 * Copyright 2023 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 * Author: nlgwcy
 * Create: 2022-02-14
 */
#include <sys/socket.h>
#include "bpf_log.h"
#include "ctx/sock_ops.h"
#include "listener.h"
#include "listener/listener.pb-c.h"
#include "filter.h"
#include "route_config.h"
#include "cluster.h"

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
        "sockops_traffic_control listener=\"%s\", addr=[%pI4h:%u]\n",
        (char *)kmesh_get_ptr_val(listener->name),
        &ip,
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
    }
    return BPF_OK;
}

#endif
#endif
char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
