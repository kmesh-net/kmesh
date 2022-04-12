/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
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

#ifndef _ENDPOINT_PB_H_
#define _ENDPOINT_PB_H_

#include "address.pb-c.h"

typedef struct {
	address_t address;
	__u16 lb_priority;
	__u16 lb_weight;
} endpoint_t;

typedef struct {
	// for loadbalance_round_robin
	map_key_t map_key;
	// for loadbalance_least_request
	__u32 lb_conn_num;
} loadbalance_t;

#endif // _ENDPOINT_PB_H_