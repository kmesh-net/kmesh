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
 * Create: 2022-02-26
 */

#ifndef _KMESH_COMMON_H_
#define _KMESH_COMMON_H_

#include "bpf_log.h"
#include "common.h"
#include "config.h"
#include "core/address.pb-c.h"


#define BPF_LOGTYPE_LISTENER		BPF_DEBUG_OFF
#define BPF_LOGTYPE_FILTERCHAIN	 	BPF_DEBUG_OFF
#define BPF_LOGTYPE_FILTER		  	BPF_DEBUG_OFF
#define BPF_LOGTYPE_CLUSTER		 	BPF_DEBUG_OFF
#define BPF_LOGTYPE_SOCKOPS		 	BPF_DEBUG_OFF
#define BPF_LOGTYPE_ROUTER		  	BPF_DEBUG_OFF
#define BPF_LOGTYPE_ROUTER_CONFIG   BPF_DEBUG_OFF
#define BPF_LOGTYPE_COMMON			BPF_DEBUG_OFF

#define BPF_DATA_MAX_LEN			226 /* this value should be
							   small that make compile success */
#define BPF_INNER_MAP_DATA_LEN	  100


#define _(P)								   \
	({										 \
		typeof(P) val;						 \
		bpf_probe_read_kernel(&val, sizeof(val), &P); \
		val;								   \
	})

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, MAP_SIZE_OF_MAX);
	__uint(map_flags, 0);
} outer_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, 1300);
	__uint(max_entries, 1);
	__uint(map_flags, 0);
} inner_map SEC(".maps");

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

enum kmesh_l7_proto_type {
	PROTO_UNKNOW 	= 0,
	PROTO_HTTP_1_1,
	PROTO_HTTP_2_0
};

enum kmesh_l7_msg_type {
	MSG_UNKNOW	= 0,
	MSG_REQUEST,
	MSG_MID_REPONSE,
	MSG_FINAL_RESPONSE
};

#define KMESH_PROTO_TYPE_WIDTH (8)
#define GET_RET_PROTO_TYPE(n) ((n) & 0xff)
#define GET_RET_MSG_TYPE(n) (((n) >> KMESH_PROTO_TYPE_WIDTH) & 0xff)

static inline int convert_sock_errno(int err)
{
	return err == 0 ? CGROUP_SOCK_OK : CGROUP_SOCK_ERR;
}

static inline int convert_sockops_ret(int err)
{
	return 0;
}

static inline void *kmesh_get_ptr_val(const void *ptr)
{
	/*
		map_in_map -- outer_map:
		key		value
		idx1	inner_map_fd1	// point to inner map1
		idx2	 inner_map_fd2	// point to inner map2
		
		structA.ptr_member1 = idx1;	// store idx in outer_map
	*/
	void *inner_map_instance = NULL;
	__u32 inner_idx = 0;
	__u64 idx = (__u64)ptr;

	BPF_LOG(DEBUG, COMMON, "kmesh_get_ptr_val idx=%u\n", idx);
	if (!ptr) {
		return NULL;
	}

	/* get inner_map_instance by idx */
	inner_map_instance = kmesh_map_lookup_elem(&outer_map, &idx);
	if (!inner_map_instance) {
		return NULL;
	}

	/* get inner_map_instance value */
	return kmesh_map_lookup_elem(inner_map_instance, &inner_idx);
}
#endif // _KMESH_COMMON_H_
