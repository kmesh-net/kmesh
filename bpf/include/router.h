/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _ROUTER_H_
#define _ROUTER_H_

#include "common.h"
#include "endpoint.h"

typedef struct {
	// TODO
	char prefix[0];
	char path[0];
} route_match_t;

typedef struct {
	map_key_t map_key_of_cluster; // map_key.index = 0
	char cluster[KMESH_NAME_LEN];
	__u16 timeout;  // default 15s
} route_action_t;

typedef struct {
	char name[KMESH_NAME_LEN];
	route_match_t match;
	route_action_t action;
} route_t;

struct bpf_map_def SEC("maps") map_of_route = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(map_key_t), // virtual_host_nameid in route_config_t
	.value_size		= sizeof(route_t),
	.max_entries	= MAP_SIZE_OF_ROUTE,
	.map_flags		= 0,
};

static inline
route_t *map_lookup_route(map_key_t *map_key)
{
	return kmesh_map_lookup_elem(&map_of_route, map_key);
}

typedef struct {
	map_key_t map_keyid_of_routes;
	char name[KMESH_NAME_LEN];

	char domains[KMESH_HTTP_DOMAIN_NUM][KMESH_HTTP_DOMAIN_LEN];
} virtual_host_t;

bpf_map_t SEC("maps") map_of_virtual_host = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(map_key_t), // route_config_nameid in route_config_t
	.value_size		= sizeof(virtual_host_t),
	.max_entries	= MAP_SIZE_OF_VIRTUAL_HOST,
	.map_flags		= 0,
};

static inline
virtual_host_t *map_lookup_virtual_host(map_key_t *map_key)
{
	return kmesh_map_lookup_elem(&map_of_virtual_host, map_key);
}

typedef struct {
	map_key_t map_keyid_of_virtual_host;
	char name[KMESH_NAME_LEN];
} route_config_t;

typedef struct {
	//char route_config_name[KMESH_NAME_LEN];
	route_config_t route_config;

	struct {
		// TODO
	} config_source;
} rds_t;

static inline
int route_check(ctx_buff_t *ctx, route_match_t *route_match)
{
	// TODO
	return 0;
}

static inline
int route_mangager(ctx_buff_t *ctx, route_action_t *route_action)
{
	// TODO
	return 0;
}

static inline
int virtual_host_check(ctx_buff_t *ctx, virtual_host_t *virtual_host)
{
	// TODO
	return 0;
}

static inline
int virtual_host_manager(ctx_buff_t *ctx, virtual_host_t *virtual_host)
{
	unsigned index, i;
	map_key_t map_key;
	route_t *route = NULL;

	map_key.nameid = virtual_host->map_keyid_of_routes.nameid;
	index = BPF_MIN(virtual_host->map_keyid_of_routes.index, MAP_SIZE_OF_PER_ROUTE);

	for (i = 0; i < index; i++) {
		map_key.index = i;

		route = map_lookup_route(&map_key);
		if (route == NULL)
			return -ENOENT;

		if (route_check(ctx, &route->match) == 0)
			break;
	}

	if (i == index)
		return -ENOENT;

	return route_mangager(ctx, &route->action);
}

static inline
int route_config_manager(ctx_buff_t *ctx, route_config_t *route_config)
{
	unsigned index, i;
	map_key_t map_key;
	virtual_host_t *virtual_host = NULL;

	map_key.nameid = route_config->map_keyid_of_virtual_host.nameid;
	index = BPF_MIN(route_config->map_keyid_of_virtual_host.index, MAP_SIZE_OF_PER_VIRTUAL_HOST);

	for (i = 0; i < index; i++) {
		map_key.index = i;

		virtual_host = map_lookup_virtual_host(&map_key);
		if (virtual_host == NULL)
			return -ENOENT;

		if (virtual_host_check(ctx, virtual_host) == 0)
			break;
	}

	if (i == index)
		return -ENOENT;

	return virtual_host_manager(ctx, virtual_host);
}

static inline
int rds_manager(ctx_buff_t *ctx, rds_t *rds)
{
	return route_config_manager(ctx, &rds->route_config);
}

#endif //_ROUTER_H_
