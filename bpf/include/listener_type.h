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

#ifndef _LISTENER_TYPE_H_
#define _LISTENER_TYPE_H_

#include "common.h"

enum listener_type {
	LISTENER_TYPE_STATIC = 0,
	LISTENER_TYPE_DYNAMIC,
};

enum listener_state {
	LISTENER_STATE_PASSIVE = 0,
	LISTENER_STATE_ACTIVE,
};

typedef struct {
	// used by map_of_cluster_t or map_of_filter_chain
	map_key_t map_key;
	//char name[KMESH_NAME_LEN];

	__u16 type;
	__u16 state;
	address_t address;
} listener_t;

#endif //_LISTENER_TYPE_H_
