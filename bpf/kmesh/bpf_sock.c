/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#include "bpf_log.h"
#include "listener.h"
#include "cluster.h"
#include "endpoint.h"

#if KMESH_ENABLE_IPV4
#if KMESH_ENABLE_TCP

__section("connect4")
int sock4_connect(struct bpf_sock_addr *ctx)
{
	return SYS_PROCEED;
}

#endif //KMESH_ENABLE_TCP
#endif //KMESH_ENABLE_IPV4

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
