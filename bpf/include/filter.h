/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2021-09-17
 */

#ifndef _FILTER_H_
#define _FILTER_H_

#include "common.h"
#include "router.h"

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
	char application_protocol[0][0];
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

int filter_chain_match_check(ctx_buff_t *ctx, filter_chain_match_t *filter_chain_match)
{
	//TODO
	return 0;
}

#endif //_FILTER_H_
