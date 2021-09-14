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
	key_index_t map_keyid_of_filter_chain;
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

#endif //_LISTENER_H_
