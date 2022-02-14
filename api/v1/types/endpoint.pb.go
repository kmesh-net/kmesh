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

package types

// #include "endpoint.pb-c.h"
import "C"

// CEndpoint = C.endpoint_t
type CEndpoint struct {
	Entry C.endpoint_t
}

type Endpoint struct {
	Address    Address `json:"address"`
	LBPriority uint16  `json:"lb_priority"`
	LBWeight   uint16  `json:"lb_weight"`
}

// CLoadbalance = C.loadbalance_t
type CLoadbalance struct {
	Entry C.loadbalance_t
}

type Loadbalance struct {
	MapKey    MapKey `json:"map_key"`
	LBConnNum uint32 `json:"lb_conn_num"`
}
