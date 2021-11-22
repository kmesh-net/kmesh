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

#ifndef _ROUTER_TYPE_H_
#define _ROUTER_TYPE_H_

#include "common.h"

typedef struct {
	// TODO
	char prefix[0];
	char path[0];
} route_match_t;

typedef struct {
	map_key_t map_key_of_cluster;
	char cluster[KMESH_NAME_LEN];
	__u16 timeout;  // default 15s
} route_action_t;

typedef struct {
	char name[KMESH_NAME_LEN];
	route_match_t match;
	route_action_t action;
} route_t;


typedef struct {
	map_key_t map_key_of_route;
	char name[KMESH_NAME_LEN];

	char domains[KMESH_HTTP_DOMAIN_NUM][KMESH_HTTP_DOMAIN_LEN];
} virtual_host_t;


typedef struct {
	map_key_t map_keyid_of_virtual_host;
	char name[KMESH_NAME_LEN];
} route_config_t;

typedef struct {
	//char route_config_name[KMESH_NAME_LEN];
	route_config_t route_config;

	struct {
		// TODO
	} config_source;
} rds_t;

#endif //_ROUTER_TYPE_H_
