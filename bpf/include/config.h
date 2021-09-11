/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#define KMESH_NAME_LEN		64
#define KMESH_TYPE_LEN		64
#define KMESH_HOST_LEN		128
#define KMESH_FILTER_CHAINS_LEN		32

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

#endif //_CONFIG_H_
