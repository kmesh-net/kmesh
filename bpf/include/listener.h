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

#define LISTENER_TYPE_STATIC		1U
#define LISTENER_TYPE_DYNAMIC		2U
	__u8 type;

#define LISTENER_STATE_PASSIVE		1U
#define LISTENER_STATE_ACTIVE		2U
	__u8 state;

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
int listener_manager(listener_t *listener, void *buf, address_t *address)
{
	map_key_t map_key;
	filter_chain_t *filter_chain = NULL;

	if (listener->state & LISTENER_STATE_PASSIVE)
		return -EBUSY;

	map_key.nameid = listener->map_key_of_filter_chain.nameid;
	for (int i = 0; i < listener->map_key_of_filter_chain.index; i++) {
		map_key.index = i;

		filter_chain = map_ops.map_get_elem(&map_of_filter_chain, &map_key);
		if (filter_chain == NULL) {
			BPF_LOG(ERR, KMESH, "map_of_filter_chain get failed, map_key %u %u\n",
					map_key.nameid, map_key.index);
			return -ENOENT;
		}

		if (filter_chain_manager(filter_chain, buf, address) == 0)
			break;
	}

	return 0;
}

#endif //_LISTENER_H_
