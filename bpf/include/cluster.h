/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
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
} load_assignment_t;

typedef struct {
	char name[KMESH_NAME_LEN];

#define CLUSTER_TYPE_STATIC				1U
#define CLUSTER_TYPE_ORIGINAL_DST		2U
#define CLUSTER_TYPE_ORIGINAL_EDS		3U
	__u16 type;

#define LB_POLICY_LEAST_REQUEST		1U
#define LB_POLICY_ROUND_ROBIN		2U
#define LB_POLICY_RANDOM			3U
	__u16 lb_policy;
	__u16 connect_timeout; //default 5s
	load_assignment_t load_assignment;
	circuit_breaker_t circuit_breaker;
} cluster_t;

bpf_map_t SEC("maps") cluster_map = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(map_key_t), // cluster_name+0 in xx
	.value_size		= sizeof(cluster_t),
	.max_entries	= MAP_SIZE_OF_CLUSTER,
	.map_flags		= 0,
};

#endif //_CLUSTER_H_
