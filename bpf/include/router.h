/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _ROUTER_H_
#define _ROUTER_H_

#include "config.h"
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
	route_action_t route;
} routes_t;

struct bpf_map_def SEC("maps") map_of_routes = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(map_key_t), // virtual_hosts_nameid in route_config_t
	.value_size		= sizeof(routes_t),
	.max_entries	= MAP_SIZE_OF_ROUTES,
	.map_flags		= 0,
};

static inline
routes_t *map_lookup_routes(map_key_t *map_key)
{
	return kmesh_map_lookup_elem(&map_of_routes, map_key);
}

typedef struct {
	map_key_t map_keyid_of_routes;
	char name[KMESH_NAME_LEN];

	char domains[KMESH_HTTP_DOMAIN_NUM][KMESH_HTTP_DOMAIN_LEN];
} virtual_hosts_t;

bpf_map_t SEC("maps") map_of_virtual_hosts = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(map_key_t), // route_config_nameid in route_config_t
	.value_size		= sizeof(virtual_hosts_t),
	.max_entries	= MAP_SIZE_OF_VIRTUAL_HOSTS,
	.map_flags		= 0,
};

static inline
virtual_hosts_t *map_lookup_virtual_host(map_key_t *map_key)
{
	return kmesh_map_lookup_elem(&map_of_virtual_hosts, map_key);
}

typedef struct {
	map_key_t map_keyid_of_virtual_host;
	char name[KMESH_NAME_LEN];
} route_config_t;

typedef struct {
	map_key_t map_keyid_of_routes;
	char route_config_name[KMESH_NAME_LEN];

	struct {
		// TODO
	} config_source;
} rds_t;

static inline
int rds_manager(ctx_buff_t *ctx, rds_t *rds)
{
	return 0;
}

static inline
int route_config_manager(ctx_buff_t *ctx, route_config_t *route_config)
{
	return 0;
}

#endif //_ROUTER_H_
