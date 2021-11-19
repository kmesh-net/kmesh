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

// #cgo CFLAGS: -I../../bpf/include
// #include "cluster.h"
import "C"
import (
	"github.com/cilium/ebpf"
	"openeuler.io/mesh/pkg/bpf"
	"unsafe"
)

// CCluster = C.cluster_t
type CCluster struct {
	Entry	C.cluster_t
}

func (cc *CCluster) Lookup(key *GoMapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Cluster.
		Lookup(key, &cc.Entry)
}

func (cc *CCluster) Update(key *GoMapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Cluster.
		Update(key, &cc.Entry, ebpf.UpdateAny)
}

func (cc *CCluster) Delete(key *GoMapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Cluster.
		Delete(key)
}

type GoCluster struct {
	//Name	string	`json:"name"`
	Type	uint16	`json:"type"`
	ConnectTimeout	uint16	`json:"connect_timeout"`
	LoadAssignment	GoLoadAssignment	`json:"load_assignment"`
	CircuitBreaker	GoCircuitBreaker	`json:"circuit_breaker"`
}

type GoLoadAssignment struct {
	MapKeyOfEndpoint		GoMapKey
	MapKeyOfLeastEndpoint	GoMapKey
	LBPolicy	uint16	`json:"lb_policy"`
}

// GoCircuitBreaker = C.circuit_breaker_t
type GoCircuitBreaker struct {
	Priority		uint16
	MaxConnections	uint16
	MaxPendingRequests	uint16
	MaxRequests		uint16
	MaxRetries		uint16
}

var (
	LBPolicyStrToC = map[string]C.uint16 {
		"ROUND_ROBIN":		C.LB_POLICY_ROUND_ROBIN,
		"LEAST_REQUEST":	C.LB_POLICY_LEAST_REQUEST,
		"RANDOM":			C.LB_POLICY_RANDOM,
	}
)

func (cc *CCluster) ToGolang() *GoCluster {
	gc := &GoCluster{}
	Memcpy(unsafe.Pointer(gc),
		unsafe.Pointer(&cc.Entry),
		unsafe.Sizeof(cc.Entry))

	return gc
}

func (gc *GoCluster) ToClang() *CCluster {
	cc := &CCluster{}
	Memcpy(unsafe.Pointer(&cc.Entry),
		unsafe.Pointer(gc),
		unsafe.Sizeof(cc.Entry))

	return cc
}
