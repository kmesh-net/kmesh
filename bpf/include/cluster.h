/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _CLUSTER_H_
#define _CLUSTER_H_

#include "config.h"

typedef struct {
#define LB_POLICY_LEAST_REQUEST		1U
#define LB_POLICY_ROUND_ROBIN		2U
#define LB_POLICY_RANDOM			3U
	__u8 lb_policy;
} loadbanance_t;

typedef struct {
	__u8 priority;
	__u16 max_connections;
	__u16 max_pending_requests;
	__u16 max_requests;;
	__u8 max_retries;
} circuit_breaker_t;

typedef struct {
	char name[KMESH_NAME_LEN];
	char namespace[KMESH_NAME_LEN];
	char host[KMESH_HOST_LEN];	//service domain
} service_t;

typedef struct {
#define CLUSTER_TYPE_STATIC				1U
#define CLUSTER_TYPE_ORIGINAL_DST		2U
#define CLUSTER_TYPE_ORIGINAL_EDS		3U
	__u8 type;

	service_t service;
	loadbanance_t loadbanance;
	circuit_breaker_t circuit_breaker;
} cluster_t;

#endif //_CLUSTER_H_
