/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _ENDPOINT_H_
#define _ENDPOINT_H_

#include "config.h"

typedef struct {
#define ADDRESS_TYPE_TCP		1U
#define ADDRESS_TYPE_UDP		2U
	__u8 protocol;

	__u32 port;	// network byte order
	union {
		__u32 ipv4;
		__u64 ipv6;
	} ip;	// network byte order
} address_t;

typedef struct {
	address_t address;
	__u16 lb_priority;
	__u16 lb_weight;
} endpoint_t;

bpf_map_t SEC("maps") map_of_endpoint = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(key_array_t), // cluster_name+id in load_assignment_t
	.value_size		= sizeof(endpoint_t),
	.max_entries	= MAP_SIZE_OF_ENDPOINT,
	.map_flags		= 0,
};

#endif //_ENDPOINT_H_