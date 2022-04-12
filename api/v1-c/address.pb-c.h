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

#ifndef _ADDRESS_PB_H_
#define _ADDRESS_PB_H_

#include <linux/types.h>

typedef struct {
	// calculated based on name in daemon
	__u32 nameid;
	// identify different services
	__u32 port;
	// initial value of the index is map_count, key range is [0, map_count)
	__u32 index;
} map_key_t;

typedef struct {
	__u32 protocol;
	// network byte order
	__u32 port;
	__u32 ipv4;
	__u32 ipv6[4];
} address_t;

#endif // _ADDRESS_PB_H_
