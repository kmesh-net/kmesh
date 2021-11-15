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

package maps
import "C"

type ClusterCircuitBreaker struct {
	Priority			uint16	`json:"priority"`
	MaxConnections		uint16	`json:"max_connections"`
	MaxPendingRequests	uint16	`json:"max_pending_requests"`
	MaxRequests			uint16	`json:"max_requests"`
	MaxRetries			uint16	`json:"max_retries"`
}

type ClusterLoadAssignment struct {
	MapKeyOfEndpoint	MapKey
	ClusterName			[C.KMESH_NAME_LEN]byte	`json:"cluster_name"`
	LBPolicy			uint16					`json:"lb_policy"`
	MapKeyOfLeastEndpoint	MapKey
}

type Cluster struct {
	Name	[C.KMESH_NAME_LEN]byte	`json:"name"`
	Type			uint16			`json:"type"`
	ConnectTimeout	uint16			`json:"connect_timeout"`
	LoadAssignment	ClusterLoadAssignment
	CircuitBreaker	ClusterCircuitBreaker
}
