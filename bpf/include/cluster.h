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

#ifndef _CLUSTER_H_
#define _CLUSTER_H_

#include "common.h"

typedef struct {
	__u16 priority;
	__u16 max_connections;
	__u16 max_pending_requests;
	__u16 max_requests;;
	__u16 max_retries;
} circuit_breaker_t;

typedef struct {
	map_key_t map_key_of_endpoint;
	char cluster_name[KMESH_NAME_LEN];

#define LB_POLICY_LEAST_REQUEST		1U
#define LB_POLICY_ROUND_ROBIN		2U
#define LB_POLICY_RANDOM			3U
	__u16 lb_policy;
	map_key_t map_key_of_least_endpoint;
} load_assignment_t;

typedef struct {
	char name[KMESH_NAME_LEN];

#define CLUSTER_TYPE_STATIC				1U
#define CLUSTER_TYPE_ORIGINAL_DST		2U
#define CLUSTER_TYPE_ORIGINAL_EDS		3U
	__u16 type;

	__u16 connect_timeout; //default 5s
	load_assignment_t load_assignment;
	circuit_breaker_t circuit_breaker;
} cluster_t;

bpf_map_t SEC("maps") map_of_cluster = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(map_key_t), // cluster_name+0 in route_action_t
	.value_size		= sizeof(cluster_t),
	.max_entries	= MAP_SIZE_OF_CLUSTER,
	.map_flags		= 0,
};

static inline
cluster_t *map_lookup_cluster(map_key_t *map_key)
{
	return kmesh_map_lookup_elem(&map_of_cluster, map_key);
}

#endif //_CLUSTER_H_
