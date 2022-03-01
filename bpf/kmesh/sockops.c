/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *	 http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: nlgwcy
 * Create: 2022-02-14
 */
#include "bpf_log.h"
#include <sys/socket.h>
#include "listener.h"
#include "listener/listener.pb-c.h"

#if KMESH_ENABLE_IPV4
#if KMESH_ENABLE_HTTP

static int sockops_traffic_control(struct bpf_sock_ops *skops, struct bpf_mem_ptr *msg)
{
	/* 1 lookup listener */
	DECLARE_VAR_ADDRESS(skops, addr);
	Listener__Listener *listener = map_lookup_listener(&addr);
	if (!listener) {
		/* no match vip/nodeport listener */
		BPF_LOG(ERR, SOCKOPS, "no match listener\n");
		return 0;
	}

	return l7_listener_manager(skops, listener);
}

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *skops)
{
#define BPF_CONSTRUCT_PTR(low_32, high_32) \
	(unsigned long long)(((unsigned long long)(high_32) << 32) + (low_32))

	int ret;
	struct bpf_mem_ptr *msg = NULL;
	
	if (skops->family != AF_INET) {
		return 0;
	}
	
	switch (skops->op) {
		case BPF_SOCK_OPS_TCP_DEFER_CONNECT_CB:
			msg = (struct bpf_mem_ptr *)BPF_CONSTRUCT_PTR(skops->args[0], skops->args[1]);
			ret = sockops_traffic_control(skops, msg);
			BPF_LOG(ERR, SOCKOPS, "sock4_traffic_control ret:%d\n", ret);
	}
	return 0;
}

#endif
#endif
char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;