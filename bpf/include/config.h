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
#define LISTENER_MAP_SIZE			128
#define CLUSTER_MAP_SIZE			128
#define ENDPOINT_MAP_SIZE			8192
#define FILTER_CHAIN_MAP_SIZE		128
#define FILTER_MAP_SIZE				128
#define LISTENER_FILTER_MAP_SIZE	64
#define VIRTUAL_HOSTS_MAP_SIZE		64
#define ROUTES_MAP_SIZE				64

// ************
// array len
#define KMESH_NAME_LEN		64
#define KMESH_TYPE_LEN		64
#define KMESH_HOST_LEN		128
#define KMESH_FILTER_CHAINS_LEN		64
#define KMESH_HTTP_DOMAIN_NUM		64
#define KMESH_HTTP_DOMAIN_LEN		128

#endif //_CONFIG_H_
