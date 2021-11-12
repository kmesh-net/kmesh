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

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stddef.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "config.h"
#include "errno.h"

#define bpf_unused __attribute__((__unused__))

#define BPF_MAX(x , y)		(((x) > (y)) ? (x) : (y))
#define BPF_MIN(x , y)		(((x) < (y)) ? (x) : (y))

#ifndef bpf_memset
#define bpf_memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef bpf_memcpy
#define bpf_memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

typedef struct bpf_map_def bpf_map_t;

#if 0
typedef struct sk_msg_md		ctx_buff_t;
#define DECLARE_VAR_ADDRESS(ctx, name) \
	address_t name = {0}; \
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
	name.port = (ctx)->user_port
#define SET_CTX_ADDRESS(ctx, address) \
	(ctx)->user_ip4  = (address)->ipv4; \
	(ctx)->user_port = (address)->port
#endif

typedef struct {
	__u32 nameid; // calculated based on name in daemon
	__u32 index; // initial value of the index is map_count, key range is [0, map_count)
} map_key_t;

static inline
void *kmesh_map_lookup_elem(bpf_map_t *map, const void *key)
{
	return bpf_map_lookup_elem(map, key);
}

static inline
int kmesh_map_delete_elem(bpf_map_t *map, const void *key)
{
	return bpf_map_delete_elem(map, key);
}

static inline
int kmesh_map_update_elem(bpf_map_t *map, const void *key, const void *value)
{
	// TODO: 重复元素，状态更新
	return bpf_map_update_elem(map, key, value, BPF_ANY);
}

// rename map to void truncation when name length exceeds BPF_OBJ_NAME_LEN = 16
#define map_of_listener			listener
#define map_of_filter_chain		filter_chain
#define map_of_filter			filter
#define map_of_virtual_host		virtual_host
#define map_of_route			route
#define map_of_cluster			cluster
#define map_of_endpoint			endpoint
#define map_of_tail_call_prog	tail_call_prog
#define map_of_tail_call_ctx	tail_call_ctx

// bpf return value
#define CGROUP_SOCK_ERR		0
#define CGROUP_SOCK_OK		1
static inline
int convert_sock_errno(int err)
{
    return err == 0 ? CGROUP_SOCK_OK : CGROUP_SOCK_ERR;
}

#endif //_COMMON_H_
