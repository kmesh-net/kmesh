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

#ifndef _CLUSTER_PB_H_
#define _CLUSTER_PB_H_

#include "address.pb-c.h"

typedef struct {
	__u16 priority;
	__u16 max_connections;
	__u16 max_pending_requests;
	__u16 max_requests;
	__u16 max_retries;
} circuit_breaker_t;

enum lb_policy {
	LB_POLICY_ROUND_ROBIN = 0,
	LB_POLICY_LEAST_REQUEST,
	LB_POLICY_RANDOM,
};

typedef struct {
	map_key_t map_key_of_endpoint;
	__u16 lb_policy;
} load_assignment_t;

enum cluster_type {
	CLUSTER_TYPE_STATIC = 0,
	CLUSTER_TYPE_ORIGINAL_DST,
	CLUSTER_TYPE_ORIGINAL_EDS,
};

typedef struct {
	//char name[KMESH_NAME_LEN];
	__u16 type;
	__u16 connect_timeout; //default 5s
	load_assignment_t load_assignment;
	circuit_breaker_t circuit_breaker;
} cluster_t;

#endif //_CLUSTER_PB_H_