/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _TAIL_CALL_H_
#define _TAIL_CALL_H_

#include "common.h"
#include "endpoint.h"

// same as linux/bpf.h MAX_TAIL_CALL_CNT
#define MAP_SIZE_OF_TAIL_CALL_PROG		32
#define MAP_SIZE_OF_TAIL_CALL_CTX		256

#define KMESH_TAIL_CALL_FILTER_CHAIN	1
#define KMESH_TAIL_CALL_FILTER			2
#define KMESH_TAIL_CALL_ROUTER			3
#define KMESH_TAIL_CALL_CLUSTER			4

#define KMESH_SOCKET_CALLS				cgroup/connect4

#ifndef __stringify
#define __stringify(X)					#X
#endif
#define SEC_TAIL(ID, KEY)				SEC(__stringify(ID) "/" __stringify(KEY))

bpf_map_t SEC("maps") map_of_tail_call_prog = {
	.type			= BPF_MAP_TYPE_PROG_ARRAY,
	.key_size		= sizeof(__u32),
	.value_size		= sizeof(__u32),
	.map_flags		= 0,
	.max_entries	= MAP_SIZE_OF_TAIL_CALL_PROG,
};

static inline
void kmesh_tail_call(ctx_buff_t *ctx, const __u32 index)
{
	bpf_tail_call(ctx, &map_of_tail_call_prog, index);
}

// save temporary variables of tail_call
bpf_map_t SEC("maps") map_of_tail_call_ctx = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(address_t),
	.value_size		= sizeof(map_key_t),
	.map_flags		= 0,
	.max_entries	= MAP_SIZE_OF_TAIL_CALL_CTX,
};

static inline
void *kmesh_tail_lookup_ctx(const address_t *key)
{
	return bpf_map_lookup_elem(&map_of_tail_call_ctx, key);
}

static inline
int kmesh_tail_delete_ctx(const address_t *key)
{
	return bpf_map_delete_elem(&map_of_tail_call_ctx, key);
}

static inline
int kmesh_tail_update_ctx(const address_t *key, const map_key_t *value)
{
	return bpf_map_update_elem(&map_of_tail_call_ctx, key, value, BPF_ANY);
}

#endif //_TAIL_CALL_H_