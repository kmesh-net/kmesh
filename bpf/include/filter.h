/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _FILTER_H_
#define _FILTER_H_

#include "config.h"
#include "router.h"
#include "endpoint.h"

typedef struct {
	//TODO
} http_filter_t;

typedef struct {
	//TODO
} server_name_t;

typedef struct {
#define FILTER_NETWORK_HTTP_CONNECTION_MANAGER	1U
	__u8 at_type;

	char stat_prefix[0];
	union {
		rds_t rds;
		route_config_t route_config;
	};
	http_filter_t http_filter;
	server_name_t server_name;
} http_connection_manager_t;

typedef struct {
#define FILTER_NETWORK_RATELIMIT	2U
	__u8 at_type;
	// TODO
	char stat_prefix[0];
	char domains[KMESH_HTTP_DOMAIN_NUM][KMESH_HTTP_DOMAIN_LEN];
	__u16 timeout;
} ratelimit_t;

typedef struct {
	char name[KMESH_NAME_LEN];
	union {
		http_connection_manager_t http_connection_manager;
		ratelimit_t ratelimit;
	} typed_config;
} filter_t;

bpf_map_t SEC("maps") map_of_filter = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(map_key_t), // listener_nameid in filter_chains_t
	.value_size		= sizeof(filter_t),
	.max_entries	= MAP_SIZE_OF_FILTER,
	.map_flags		= 0,
};

static inline
filter_t *map_lookup_filter(map_key_t *map_key)
{
	return kmesh_map_lookup_elem(&map_of_filter, map_key);
}

typedef struct {
	__u32 destination_port;
	char transport_protocol[0];
	char application_protocols[0][0];
} filter_chain_match_t;

typedef struct {
	map_key_t map_key_of_filter;
	// name = listener_name

	filter_chain_match_t filter_chain_match;
} filter_chain_t;

bpf_map_t SEC("maps") map_of_filter_chain = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(map_key_t), // listener_nameid in listener_t
	.value_size		= sizeof(filter_chain_t),
	.max_entries	= MAP_SIZE_OF_FILTER_CHAIN,
	.map_flags		= 0,
};

static inline
filter_chain_t *map_lookup_filter_chain(map_key_t *map_key)
{
	return kmesh_map_lookup_elem(&map_of_filter_chain, map_key);
}

static inline
int filter_chain_match_check(filter_chain_match_t *filter_chain_match, void *buf)
{
	//TODO
	return 0;
}

static inline
int *filter_manager(filter_t *filter, void *buf, address_t *address)
{
	
	return 0;
}

static inline
int filter_chain_manager(filter_chain_t *filter_chain, void *buf, address_t *address)
{
	int ret;
	__u32 index;
	map_key_t map_key;
	filter_t *filter = NULL;

	ret = filter_chain_match_check(&filter_chain->filter_chain_match, NULL);
	if (ret != 0) {
		BPF_LOG(DEBUG, KMESH, "filter_chain_match_check failed, ret %d\n", ret);
		return ret;
	}

	map_key.nameid = filter_chain->map_key_of_filter.nameid;
	index = BPF_MIN(filter_chain->map_key_of_filter.index, MAP_SIZE_OF_FILTER);

	for (int i = 0; i < index; i++) {
		map_key.index = i;

		filter = map_lookup_filter(&map_key);
		if (filter == NULL) {
			BPF_LOG(DEBUG, KMESH, "map_of_filter get failed, map_key %u %u\n",
					map_key.nameid, map_key.index);
			return -ENOENT;
		}

		if (filter_manager(filter, NULL, address) == 0)
			break;
	}

	return 0;
}

#endif //_FILTER_H_
