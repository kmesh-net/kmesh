/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _CLUSTER_H_
#define _CLUSTER_H_

#include "config.h"

typedef struct {
	__u8 priority;
	__u16 max_connections;
	__u16 max_pending_requests;
	__u16 max_requests;;
	__u8 max_retries;
} circuit_breaker_t;

typedef struct {
#define ENDPOINT_MAP_KEY_ID		key_id
	key_index_t key_id;
	char cluster_name[KMESH_NAME_LEN];
} load_assignment_t;

typedef struct {
	char name[KMESH_NAME_LEN];

#define CLUSTER_TYPE_STATIC				1U
#define CLUSTER_TYPE_ORIGINAL_DST		2U
#define CLUSTER_TYPE_ORIGINAL_EDS		3U
	__u8 type;

#define LB_POLICY_LEAST_REQUEST		1U
#define LB_POLICY_ROUND_ROBIN		2U
#define LB_POLICY_RANDOM			3U
	__u8 lb_policy;
	__u16 connect_timeout; //default 5s
	load_assignment_t load_assignment;
	circuit_breaker_t circuit_breaker;
} cluster_t;

struct bpf_map_def SEC("maps") cluster_map = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(key_name_t), // cluster_name in xx
	.value_size		= sizeof(cluster_t),
	.max_entries	= CLUSTER_MAP_SIZE,
	.map_flags		= 0,
};

#endif //_CLUSTER_H_
