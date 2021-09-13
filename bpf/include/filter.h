/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _FILTER_H_
#define _FILTER_H_

#include "config.h"
#include "router.h"

typedef struct {
	// TODO
} rds_t;

typedef struct {
#define FILTER_NETWORK_HTTP_CONNECTION_MANAGER	1U
	__u8 at_type;

	char stat_prefix[0];
	union {
		rds_t rds;
		route_config_t route_config;
	} backend;
	http_filter_t http_filter;
	server_name_t server_name;
} http_connection_manager_t;

typedef struct {
#define FILTER_NETWORK_RATELIMIT	2U
	__u8 at_type;
	// TODO
	char stat_prefix[0];
	char domain[0];
	__u16 timeout;
} ratelimit_t;

typedef struct {
	char name[KMESH_NAME_LEN];
	union {
		http_connection_manager_t http_connection_manager;
		ratelimit_t ratelimit;
	} typed_config;
} filter_t;

struct bpf_map_def SEC("maps") filter_map = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(key_array_t), // listener_name+id in filter_chains_t
	.value_size		= sizeof(filter_t),
	.max_entries	= FILTER_MAP_SIZE,
	.map_flags		= 0,
};

typedef struct {
	__u32 destination_port;
	// TODO
} filter_chain_match_t;

typedef struct {
#define FILTER_MAP_KEY_ID		key_id
	key_index_t key_id; // using listener_name

	filter_chain_match_t filter_chain_match;
} filter_chain_t;

struct bpf_map_def SEC("maps") filter_chain_map = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(key_array_t), // listener_name+id in listener_t
	.value_size		= sizeof(filter_chain_t),
	.max_entries	= FILTER_CHAIN_MAP_SIZE,
	.map_flags		= 0,
};

#endif //_FILTER_H_
