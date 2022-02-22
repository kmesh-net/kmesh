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
 * Create: 2021-10-09
 */

package api

// #cgo pkg-config: api-v1-c
// #include "listener.pb-c.h"
import "C"

// CListener = C.listener_t
type CListener struct {
	Entry C.listener_t
}

type Listener struct {
	MapKey MapKey
	//Name	string	`json:"name"`
	Type    uint16  `json:"type"`
	State   uint16  `json:"state"`
	Address Address `json:"address"`
}
