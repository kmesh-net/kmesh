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
// #include "cluster.pb-c.h"
import "C"

// CCluster = C.cluster_t
type CCluster struct {
	Entry C.cluster_t
}

type Cluster struct {
	//Name	string	`json:"name"`
	Type           uint16         `json:"type"`
	ConnectTimeout uint16         `json:"connect_timeout"`
	LoadAssignment LoadAssignment `json:"load_assignment"`
	CircuitBreaker CircuitBreaker `json:"circuit_breaker"`
}

type LoadAssignment struct {
	MapKeyOfEndpoint MapKey
	LBPolicy         uint16	`json:"lb_policy"`
}

// CircuitBreaker = C.circuit_breaker_t
type CircuitBreaker struct {
	Priority		uint16
	MaxConnections	uint16
	MaxPendingRequests	uint16
	MaxRequests		uint16
	MaxRetries		uint16
}

var (
	LBPolicyStrToC = map[string]C.uint {
		"ROUND_ROBIN":		C.LB_POLICY_ROUND_ROBIN,
		"LEAST_REQUEST":	C.LB_POLICY_LEAST_REQUEST,
		"RANDOM":			C.LB_POLICY_RANDOM,
	}
)
