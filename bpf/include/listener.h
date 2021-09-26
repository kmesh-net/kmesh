/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _LISTENER_H_
#define _LISTENER_H_

#include "config.h"
#include "filter.h"
#include "endpoint.h"

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
	__u32 index;
	map_key_t map_key;
	filter_chain_t *filter_chain = NULL;

	if (listener->state & LISTENER_STATE_PASSIVE)
		return -EBUSY;

	map_key.nameid = listener->map_key_of_filter_chain.nameid;
	index = BPF_MIN(listener->map_key_of_filter_chain.index, MAP_SIZE_OF_FILTER_CHAIN);

	for (int i = 0; i < index; i++) {
		map_key.index = i;

		filter_chain = map_lookup_filter_chain(&map_key);
		if (filter_chain == NULL) {
			BPF_LOG(ERR, KMESH, "map_of_filter_chain get failed, map_key %u %u\n",
					map_key.nameid, map_key.index);
			return -ENOENT;
		}

		if (filter_chain_manager(ctx, filter_chain) == 0)
			return 0;
	}

	return -ENOENT;
}

#endif //_LISTENER_H_
