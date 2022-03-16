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
 * Create: 2022-02-17
 */

#ifndef _KMESH_TAIL_CALL_H_
#define _KMESH_TAIL_CALL_H_

#include "kmesh_common.h"

// same as linux/bpf.h MAX_TAIL_CALL_CNT
#define MAP_SIZE_OF_TAIL_CALL_PROG		  32
#define MAP_SIZE_OF_TAIL_CALL_CTX		   256

#define KMESH_SOCKOPS_CALLS				 sockops

typedef enum {
	KMESH_TAIL_CALL_LISTENER = 1,
	KMESH_TAIL_CALL_FILTER_CHAIN,
	KMESH_TAIL_CALL_FILTER,
	KMESH_TAIL_CALL_ROUTER,
	KMESH_TAIL_CALL_CLUSTER,
	KMESH_TAIL_CALL_ROUTER_CONFIG,
} tail_call_index_t;

bpf_map_t SEC("maps") map_of_tail_call_prog = {
	.type		   = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size	   = sizeof(__u32),
	.value_size	 = sizeof(__u32),
	.map_flags	  = 0,
	.max_entries	= MAP_SIZE_OF_TAIL_CALL_PROG,
};

static inline
void kmesh_tail_call(ctx_buff_t *ctx, const __u32 index)
{
	bpf_tail_call(ctx, &map_of_tail_call_prog, index);
}

typedef struct {
	__u32 tail_call_index;
	address_t address;
} ctx_key_t;

typedef struct {
	union {
		//void *val;
		__u64 val;
		char data[BPF_DATA_MAX_LEN];
	};
	struct bpf_mem_ptr *msg;
} ctx_val_t;

// save temporary variables of tail_call
bpf_map_t SEC("maps") map_of_tail_call_ctx = {
	.type		   = BPF_MAP_TYPE_HASH,
	.key_size	   = sizeof(ctx_key_t),
	.value_size	 = sizeof(ctx_val_t),
	.map_flags	  = 0,
	.max_entries	= MAP_SIZE_OF_TAIL_CALL_CTX,
};

static inline
ctx_val_t *kmesh_tail_lookup_ctx(const ctx_key_t *key)
{
	return bpf_map_lookup_elem(&map_of_tail_call_ctx, key);
}

static inline
int kmesh_tail_delete_ctx(const ctx_key_t *key)
{
	return bpf_map_delete_elem(&map_of_tail_call_ctx, key);
}

static inline
int kmesh_tail_update_ctx(const ctx_key_t *key, const ctx_val_t *value)
{
	return bpf_map_update_elem(&map_of_tail_call_ctx, key, value, BPF_ANY);
}

#endif //_TAIL_CALL_H_
