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
	char stat_prefix[0];

#define HTTP_CONNECTION_MANAGER_RDS				1
#define HTTP_CONNECTION_MANAGER_ROUTE_CONFIG	2
	__u16 at_type;

	union {
		rds_t rds;
		route_config_t route_config;
	};
	http_filter_t http_filter;
	char server_name[0];
} http_connection_manager_t;

typedef struct {
	// TODO
	char stat_prefix[0];
	char domains[KMESH_HTTP_DOMAIN_NUM][KMESH_HTTP_DOMAIN_LEN];
	__u16 timeout;
} ratelimit_t;

typedef struct {
	char name[KMESH_NAME_LEN];

#define FILTER_NETWORK_HTTP_CONNECTION_MANAGER	1
#define FILTER_NETWORK_RATELIMIT				2
	__u16 at_type;

	// typed_config
	union {
		http_connection_manager_t http_connection_manager;
		ratelimit_t ratelimit;
	};
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
int http_filter_manager(ctx_buff_t *ctx, http_filter_t *http_filter)
{
	//TODO
	return 0;
}

static inline
int filter_handle_http_connection_manager(
	ctx_buff_t *ctx,
	http_connection_manager_t *http_connection_manager)
{
	int ret;

	switch (http_connection_manager->at_type) {
		case HTTP_CONNECTION_MANAGER_RDS:
			ret = rds_manager(ctx, &http_connection_manager->rds);
			break;
		case HTTP_CONNECTION_MANAGER_ROUTE_CONFIG:
			ret = route_config_manager(ctx, &http_connection_manager->route_config);
			break;
		default:
			BPF_LOG(ERR, KMESH, "http_connection_manager at_type is wrong\n");
			ret = -ENOENT;
			break;
	}

	ret |= http_filter_manager(ctx, &http_connection_manager->http_filter);

	return ret;
}

static inline
int filter_manager(ctx_buff_t *ctx, filter_t *filter)
{
	int ret;

	switch (filter->at_type) {
		case FILTER_NETWORK_HTTP_CONNECTION_MANAGER:
			ret = filter_handle_http_connection_manager(ctx, &filter->http_connection_manager);
			break;
		case FILTER_NETWORK_RATELIMIT:
			//TODO
			//ret = filter_handle_rds(filter->ratelimit);
			ret = -ENOENT;
			break;
		default:
			BPF_LOG(ERR, KMESH, "filter at_type is wrong\n");
			ret = -ENOENT;
			break;
	}

	return ret;
}

static inline
int filter_chain_match_check(filter_chain_match_t *filter_chain_match, void *buf)
{
	//TODO
	return 0;
}

static inline
int filter_chain_manager(ctx_buff_t *ctx, filter_chain_t *filter_chain)
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

		if (filter_manager(ctx, filter) == 0)
			return 0;
	}

	return -ENOENT;
}

#endif //_FILTER_H_
