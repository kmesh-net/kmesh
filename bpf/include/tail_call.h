/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _COMMON_H_
#define _COMMON_H_

#include "config.h"
#include "common.h"

// same as linux/bpf.h MAX_TAIL_CALL_CNT
#define MAP_SIZE_OF_TAIL_CALL_PROG		32
#define MAP_SIZE_OF_TAIL_CALL_CTX		32

#define KMESH_TAIL_CALL_FILTER			1
#define KMESH_TAIL_CALL_ROUTER			2
#define KMESH_TAIL_CALL_CLUSTER			3

bpf_map_t SEC("maps") map_of_tail_call_prog = {
	.type			= BPF_MAP_TYPE_PROG_ARRAY,
	.key_size		= sizeof(__u32),
	.value_size		= sizeof(__u32),
	.map_flags		= 0,
	.max_entries	= MAP_SIZE_OF_TAIL_CALL_PROG,
};

static inline
int kmesh_tail_call(ctx_buff_t *ctx, const __u32 index)
{
	return bpf_tail_call(ctx, &map_of_tail_call_prog, index);
}

bpf_map_t SEC("maps") map_of_tail_call_ctx = {
	.type			= BPF_MAP_TYPE_PROG_ARRAY,
	.key_size		= sizeof(address_t),
	.value_size		= sizeof(map_key_t),
	.map_flags		= 0,
	.max_entries	= MAP_SIZE_OF_TAIL_CALL_CTX,
};

static inline
map_key_t *kmesh_lookup_tail_ctx(const address_t *key)
{
	return bpf_map_lookup_elem(&map_of_tail_call_ctx, key);
}

static inline
map_key_t *kmesh_delete_tail_ctx(const address_t *key)
{
	return bpf_map_delete_elem(&map_of_tail_call_ctx, key);
}

static inline
int kmesh_update_tail_ctx(const address_t *key, const map_key_t *value)
{
	return bpf_map_update_elem(&map_of_tail_call_ctx, key, value, BPF_ANY);
}

#endif //_COMMON_H_
