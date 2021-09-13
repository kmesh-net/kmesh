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
#define FILTER_CHAIN_MAP_KEY_ID	key_id
	key_index_t key_id;
	char name[KMESH_NAME_LEN];

#define LISTENER_TYPE_STATIC		1U
#define LISTENER_TYPE_DYNAMIC		2U
	__u8 type;

#define LISTENER_STATE_PASSIVE		1U
#define LISTENER_STATE_ACTIVE		2U
	__u8 state;

	address_t address;
} listener_t;

struct bpf_map_def SEC("maps") listener_map = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(address_t),
	.value_size		= sizeof(listener_t),
	.max_entries	= LISTENER_MAP_SIZE,
	.map_flags		= 0,
};

#endif //_LISTENER_H_
