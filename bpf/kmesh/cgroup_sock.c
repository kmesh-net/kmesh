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
#include "listener.h"
#include "listener/listener.pb-c.h"
#if KMESH_ENABLE_IPV4
#if KMESH_ENABLE_HTTP

#ifdef DECLARE_VAR_ADDRESS
#undef DECLARE_VAR_ADDRESS
#define DECLARE_VAR_ADDRESS(ctx, name) \
	address_t name = {0}; \
	name.ipv4 = (ctx)->user_ip4; \
	name.port = (ctx)->user_port; \
	name.protocol = (ctx)->protocol
#endif

static inline
int sock4_traffic_control(struct bpf_sock_addr *ctx)
{
	int ret;
	Listener__Listener *listener = NULL;

	DECLARE_VAR_ADDRESS(ctx, address);

	listener = map_lookup_listener(&address);
	if (listener == NULL) {
		return -ENOENT;
	}
	
#if KMESH_ENABLE_HTTP
	return 2;	// defer conn
#else //KMESH_ENABLE_HTTP
	ret = l4_listener_manager(ctx, lisdemotener);
#endif //KMESH_ENABLE_HTTP
	if (ret != 0) {
		BPF_LOG(ERR, KMESH, "listener_manager failed, ret %d\n", ret);
		return ret;
	}

	return 0;
}

SEC("cgroup/connect4")
int cgroup_connect4_prog(struct bpf_sock_addr *ctx)
{
	int ret = sock4_traffic_control(ctx);
#if KMESH_ENABLE_HTTP
	if (ret == 2) {	// defer conn
		return ret;
	}
#endif
	return CGROUP_SOCK_OK;
}

#endif //KMESH_ENABLE_TCP
#endif //KMESH_ENABLE_IPV4

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
