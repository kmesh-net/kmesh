/*
 * Copyright 2024 The Kmesh Authors.
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

 * Author: kwb0523
 * Create: 2024-01-20
 */

#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include "bpf_log.h"
#include "ctx/sock_addr.h"
#include "frontend.h"
#include "bpf_common.h"

static void ctx4_dnat(void *ctx, struct ip_addr *addr, __u32 port)
{
    BPF_LOG(DEBUG, KMESH, "ctx4_dnat\n");
}

static void ctx6_dnat(void *ctx, struct ip_addr *addr, __u32 port)
{
    BPF_LOG(DEBUG, KMESH, "ctx6_dnat\n");
}

static inline int sock_traffic_control(struct bpf_sock_addr *ctx, struct ctx_info *info)
{
    int ret;
    frontend_value *frontend_v = NULL;

    if (!check_kmesh_enabled(ctx) || ctx->protocol != IPPROTO_TCP)
        return 0;

    DECLARE_FRONTEND_KEY(ctx, &(info->vip), frontend_k);

    BPF_LOG(DEBUG, KMESH, "origin addr=[%u:%u:%u]\n", ctx->user_family, ctx->user_ip4, ctx->user_port);
    frontend_v = map_lookup_frontend(&frontend_k);
    if (!frontend_v) {
        return -ENOENT;
    }

    BPF_LOG(DEBUG, KMESH, "bpf find frontend addr=[%u:%u]\n", ctx->user_ip4, ctx->user_port);
    ret = frontend_manager(ctx, frontend_v, info);
    if (ret != 0) {
        if (ret != -ENOENT)
            BPF_LOG(ERR, KMESH, "frontend_manager failed, ret:%d\n", ret);
        return ret;
    }

    return 0;
}

SEC("cgroup/connect4")
int cgroup_connect4_prog(struct bpf_sock_addr *ctx)
{
    struct ctx_info info = {
        .vip.ip4 = ctx->user_ip4,
    };

    if (conn_from_cni_sim_add(ctx)) {
        record_netns_cookie(ctx);
        // return failed, cni sim connect 0.0.0.1:929(0x3a1)
        // A normal program will not connect to this IP address
        return CGROUP_SOCK_OK;
    }
    if (conn_from_cni_sim_delete(ctx)) {
        remove_netns_cookie(ctx);
        return CGROUP_SOCK_OK;
    }

    int ret = sock_traffic_control(ctx, &info);
    if (ret) {
        BPF_LOG(ERR, KMESH, "sock_traffic_control failed:%d\n", ret);
        return CGROUP_SOCK_OK;
    }
    if (info.via_waypoint) {
        //
        kmesh_workload_tail_call(ctx, TAIL_CALL_CONNECT4_INDEX);

        // if tail call failed will run this code
        BPF_LOG(ERR, KMESH, "workload tail call failed, err is %d\n", ret);
        return CGROUP_SOCK_OK;
    }

    SET_CTX_ADDRESS4(ctx, &info.dnat_ip, info.dnat_port);
    return CGROUP_SOCK_OK;
}

SEC("cgroup/connect6")
int cgroup_connect6_prog(struct bpf_sock_addr *ctx)
{
    struct ctx_info info = {0};
    bpf_memcpy(info.vip.ip6, ctx->user_ip6, IPV6_ADDR_LEN);

    int ret = sock_traffic_control(ctx, &info);
    if (ret) {
        BPF_LOG(ERR, KMESH, "sock_traffic_control failed:%d\n", ret);
        return CGROUP_SOCK_OK;
    }
    if (info.via_waypoint) {
        //
        kmesh_workload_tail_call(ctx, TAIL_CALL_CONNECT4_INDEX);

        // if tail call failed will run this code
        BPF_LOG(ERR, KMESH, "[connect6]workload tail call failed, err is %d\n", ret);
        return CGROUP_SOCK_OK;
    }

    SET_CTX_ADDRESS6(ctx, &info.dnat_ip, info.dnat_port);
    return CGROUP_SOCK_OK;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
