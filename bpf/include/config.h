/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

// ************
// options
#define KMESH_MODULE_ON			1
#define KMESH_MODULE_OFF		0

// L3
#define KMESH_ENABLE_IPV4		KMESH_MODULE_ON
#define KMESH_ENABLE_IPV6		KMESH_MODULE_OFF
// L4
#define KMESH_ENABLE_TCP		KMESH_MODULE_ON
#define KMESH_ENABLE_UDP		KMESH_MODULE_OFF
// L7
#define KMESH_ENABLE_HTTP		KMESH_MODULE_OFF

// ************
// map size
#define MAP_SIZE_OF_LISTENER		128
#define MAP_SIZE_OF_FILTER_CHAIN	128
#define MAP_SIZE_OF_FILTER			128
#define MAP_SIZE_OF_VIRTUAL_HOSTS	64
#define MAP_SIZE_OF_ROUTES			64
#define MAP_SIZE_OF_CLUSTER			128
#define MAP_SIZE_OF_ENDPOINT		8192

// ************
// array len
#define KMESH_NAME_LEN				64
#define KMESH_TYPE_LEN				64
#define KMESH_HOST_LEN				128
#define KMESH_FILTER_CHAINS_LEN		64
#define KMESH_HTTP_DOMAIN_NUM		64
#define KMESH_HTTP_DOMAIN_LEN		128

#endif //_CONFIG_H_
