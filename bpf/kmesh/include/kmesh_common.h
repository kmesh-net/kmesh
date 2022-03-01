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
 * Create: 2022-02-26
 */

#ifndef _KMESH_COMMON_H_
#define _KMESH_COMMON_H_

#include "common.h"
#include "config.h"
#include "core/address.pb-c.h"


#define BPF_LOGTYPE_LISTENER		BPF_DEBUG_ON
#define BPF_LOGTYPE_FILTERCHAIN	 BPF_DEBUG_ON
#define BPF_LOGTYPE_FILTER		  BPF_DEBUG_ON
#define BPF_LOGTYPE_CLUSTER		 BPF_DEBUG_ON
#define BPF_LOGTYPE_SOCKOPS		 BPF_DEBUG_ON
#define BPF_LOGTYPE_ROUTER		  BPF_DEBUG_ON
#define BPF_LOGTYPE_ROUTER_CONFIG   BPF_DEBUG_ON

#define BPF_DATA_MAX_LEN			32
#define BPF_INNER_MAP_DATA_LEN	  100


#define _(P)								   \
	({										 \
		typeof(P) val;						 \
		bpf_probe_read_kernel(&val, sizeof(val), &P); \
		val;								   \
	})

bpf_map_t SEC("maps") outer_map = {
	.type			= BPF_MAP_TYPE_ARRAY_OF_MAPS,
	.key_size		= sizeof(__u32),
	.value_size		= sizeof(__u32),
	.max_entries	= MAP_SIZE_OF_MAX,
	.map_flags		= 0,
};

#if 1
typedef struct bpf_sock_ops		ctx_buff_t;
#define DECLARE_VAR_ADDRESS(ctx, name) \
	address_t name = {0}; \
	bpf_memset(&name, 0, sizeof(name)); \
	name.ipv4 = (ctx)->remote_ip4; \
	name.port = (ctx)->remote_port
#define SET_CTX_ADDRESS(ctx, address) \
	(ctx)->remote_ip4  = (address)->ipv4; \
	(ctx)->remote_port = (address)->port
#else
typedef struct bpf_sock_addr	ctx_buff_t;
#define DECLARE_VAR_ADDRESS(ctx, name) \
	address_t name = {0}; \
	name.ipv4 = (ctx)->user_ip4; \
	name.port = (ctx)->user_port; \
	name.protocol = (ctx)->protocol
#define SET_CTX_ADDRESS(ctx, address) \
	(ctx)->user_ip4  = (address)->ipv4; \
	(ctx)->user_port = (address)->port; \
	(ctx)->protocol = (address)->protocol
#endif

typedef Core__SocketAddress address_t;

// bpf return value
#define CGROUP_SOCK_ERR		0
#define CGROUP_SOCK_OK		1
static inline
int convert_sock_errno(int err)
{
	return err == 0 ? CGROUP_SOCK_OK : CGROUP_SOCK_ERR;
}

static inline 
int convert_sockops_ret(int err)
{
	return 0;
}

static inline
void * kmesh_get_ptr_val(const void *ptr)
{
	/* 
		map_in_map -- outer_map:
		key		value
		idx1	inner_map_fd1	// point to inner map1
		idx2	 inner_map_fd2	// point to inner map2
		
		structA.ptr_member1 = idx1;	// store idx in outer_map
	*/
	void *inner_map = NULL;
	__u32 inner_idx = 0;
	__u64 idx = (__u64)ptr;

	if (!ptr) {
		return NULL;
	}

	/* get inner_map by idx */
	inner_map = kmesh_map_lookup_elem(&outer_map, &idx);
	if (!inner_map) {
		return NULL;
	}

	/* get inner_map value */
	return kmesh_map_lookup_elem(inner_map, &inner_idx);
}
#endif //_KMESH_COMMON_H_
