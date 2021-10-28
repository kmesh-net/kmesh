/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
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
	ret = listener_manager(ctx, listener);
	if (ret != 0) {
		BPF_LOG(ERR, KMESH, "listener_manager failed, ret %d\n", ret);
		return ret;
	}

	return 0;
}

#endif //KMESH_ENABLE_TCP
#endif //KMESH_ENABLE_IPV4


#if KMESH_ENABLE_IPV4
SEC("cgroup/connect4")
int sock_connect4(struct bpf_sock_addr *ctx)
{
#if KMESH_ENABLE_TCP
	sock4_traffic_control(ctx);
#endif //KMESH_ENABLE_TCP
	return CGROUP_SOCK_OK;
}
#endif //KMESH_ENABLE_IPV4

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
