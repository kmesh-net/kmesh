/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _ROUTER_H_
#define _ROUTER_H_

#include "config.h"

typedef struct {
	// TODO
	char prefix[0];
	char path[0];
} match_t;

typedef struct {
	// TODO
	char cluster[0];
	char cluster_header[0];
	__u16 timeout;  // default 15s
} route_t;

typedef struct {
	char name[KMESH_NAME_LEN];
	match_t match;
	route_t route;
} routes_t;

struct bpf_map_def SEC("maps") routes_map = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(key_array_t), // virtual_hosts_name+id in route_config_t
	.value_size		= sizeof(routes_t),
	.max_entries	= ROUTES_MAP_SIZE,
	.map_flags		= 0,
};

typedef struct {
#define ROUTES_MAP_KEY_ID		key_id
	key_index_t key_id;
	char name[KMESH_NAME_LEN];

	char domains[KMESH_HTTP_DOMAIN_NUM][KMESH_HTTP_DOMAIN_LEN];
} virtual_hosts_t;

struct bpf_map_def SEC("maps") virtual_hosts_map = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(key_array_t), // route_config_name+id in route_config_t
	.value_size		= sizeof(virtual_hosts_t),
	.max_entries	= VIRTUAL_HOSTS_MAP_SIZE,
	.map_flags		= 0,
};

typedef struct {
#define VIRTUAL_HOST_MAP_KEY_ID		key_id
	key_index_t key_id;
	char name[KMESH_NAME_LEN];
} route_config_t;

#endif //_ROUTER_H_
