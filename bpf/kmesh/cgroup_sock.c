/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2021-09-17
 */

#include "bpf_log.h"
#include "listener.h"

#if KMESH_ENABLE_IPV4
#if KMESH_ENABLE_TCP

static inline
int sock4_traffic_control(struct bpf_sock_addr *ctx)
{
	int ret;
	listener_t *listener = NULL;

	DECLARE_VAR_ADDRESS(ctx, address);

	listener = map_lookup_listener(&address);
	if (listener == NULL) {
		BPF_LOG(DEBUG, KMESH, "map_of_listener get failed, ip4 %u, port %u\n",
				address.ipv4, address.port);
		return -ENOENT;
	}

#if KMESH_ENABLE_HTTP
	ret = l7_listener_manager(ctx, listener);
#else //KMESH_ENABLE_HTTP
	ret = l4_listener_manager(ctx, listener);
#endif //KMESH_ENABLE_HTTP
	if (ret != 0) {
		BPF_LOG(ERR, KMESH, "listener_manager failed, ret %d\n", ret);
		return ret;
	}

	return 0;
}

SEC("cgroup/connect4")
int sock_connect4(struct bpf_sock_addr *ctx)
{
	/*
	struct sk_msg_md {
		__bpf_md_ptr(void *, data);
		__bpf_md_ptr(void *, data_end);
		...
		__u32 remote_ip4;
		__u32 remote_port;
		__u32 size;
		...
	}; */
	sock4_traffic_control(ctx);
	return CGROUP_SOCK_OK;
}

#endif //KMESH_ENABLE_TCP
#endif //KMESH_ENABLE_IPV4

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
