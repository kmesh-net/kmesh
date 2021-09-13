/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _LISTENER_H_
#define _LISTENER_H_

#include "config.h"
#include "endpoint.h"

typedef struct {
	char name[KMESH_NAME_LEN];

#define FILTER_TYPE_NETWORK		1U
#define FILTER_TYPE_HTTP		2U
	__u8 type;
} filter_t;

typedef struct {
	char name[KMESH_NAME_LEN];

#define LISTENER_TYPE_STATIC		1U
#define LISTENER_TYPE_DYNAMIC		2U
	__u8 type;

	address_t address;
	filter_t filter_chains[KMESH_FILTER_CHAINS_LEN];
} listener_t;

#endif //_LISTENER_H_
