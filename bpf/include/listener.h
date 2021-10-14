/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _LISTENER_H_
#define _LISTENER_H_

#include "bpf_log.h"
#include "filter.h"
#include "endpoint.h"
#include "tail_call.h"

typedef struct {
	map_key_t map_key_of_filter_chain;
	char name[KMESH_NAME_LEN];

#define LISTENER_TYPE_STATIC		1
#define LISTENER_TYPE_DYNAMIC		2
	__u16 type;

#define LISTENER_STATE_PASSIVE		1
#define LISTENER_STATE_ACTIVE		2
	__u16 state;

	address_t address;
} listener_t;

bpf_map_t SEC("maps") map_of_listener = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(address_t),
	.value_size		= sizeof(listener_t),
	.max_entries	= MAP_SIZE_OF_LISTENER,
	.map_flags		= 0,
};

static inline
listener_t *map_lookup_listener(address_t *address)
{
	return kmesh_map_lookup_elem(&map_of_listener, address);
}

static inline
int listener_manager(ctx_buff_t *ctx, listener_t *listener)
{
	unsigned index, i;
	map_key_t map_key;
	filter_chain_t *filter_chain = NULL;

	DECLARE_VAR_ADDRESS(ctx, address);

	if (listener->state & LISTENER_STATE_PASSIVE)
		return -EBUSY;

	map_key.nameid = listener->map_key_of_filter_chain.nameid;
	index = BPF_MIN(listener->map_key_of_filter_chain.index, MAP_SIZE_OF_PER_FILTER_CHAIN);

	for (i = 0; i < index; i++) {
		map_key.index = i;

		filter_chain = map_lookup_filter_chain(&map_key);
		if (filter_chain == NULL)
			return -ENOENT;

		if (filter_chain_match_check(ctx, &filter_chain->filter_chain_match) == 0)
			break;
	}

	if (i == index)
		return -ENOENT;

	if (kmesh_tail_update_ctx(&address, &map_key) != 0)
		return -ENOSPC;
	kmesh_tail_call(ctx, KMESH_TAIL_CALL_FILTER_CHAIN);
	kmesh_tail_delete_ctx(&address);

	return 0;
}

#endif //_LISTENER_H_
