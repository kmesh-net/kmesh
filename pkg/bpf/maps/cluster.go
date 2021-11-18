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
	Endpoints	[]CEndpoint
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
	Name	string	`json:"name"`
	Type	string	`json:"type"`
	ConnectTimeout	uint16	`json:"connect_timeout"`
	LoadAssignment	GoLoadAssignment	`json:"load_assignment"`
	CircuitBreaker	GoCircuitBreaker	`json:"circuit_breaker"`
}

type GoLoadAssignment struct {
	LBPolicy	string	`json:"lb_policy"`
	Endpoints	[]GoEndpoint	`json:"endpoints"`
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
	LBPolicyToC = map[string]C.ushort {
		"LEAST_REQUEST":	C.LB_POLICY_LEAST_REQUEST,
		"ROUND_ROBIN":		C.LB_POLICY_ROUND_ROBIN,
		"RANDOM":			C.LB_POLICY_RANDOM,
	}
	LBPolicyToGo = map[C.ushort]string {
		C.LB_POLICY_LEAST_REQUEST:	"LEAST_REQUEST",
		C.LB_POLICY_ROUND_ROBIN:	"ROUND_ROBIN",
		C.LB_POLICY_RANDOM:			"RANDOM",
	}
)

func (cc *CCluster) ToGolang() *GoCluster {
	gc := &GoCluster{}
	gc.Name = C.GoString( (*C.char)(unsafe.Pointer(cc.Entry.name)) )
	//TODO: gc.Type = cc.Entry._type
	gc.ConnectTimeout = cc.Entry.connect_timeout

	gc.LoadAssignment.LBPolicy = LBPolicyToGo[cc.Entry.load_assignment.lb_policy]
	ce := CEndpoint{}
	key := GoMapKey{}
	// TODO: key.NameID =
	for true {
		// until cannot lookup from map
		if err := ce.Lookup(&key); err != nil {
			break
		}
		gc.LoadAssignment.Endpoints = append(gc.LoadAssignment.Endpoints, *ce.ToGolang())
		key.Index++
	}

	Memcpy(unsafe.Pointer(&gc.CircuitBreaker),
		unsafe.Pointer(&cc.Entry.circuit_breaker),
		unsafe.Sizeof(gc.CircuitBreaker))

	return gc
}

func (gc *GoCluster) ToClang() *CCluster {
	cc := &CCluster{}
	StrcpyToC(unsafe.Pointer(&cc.Entry.name),
		unsafe.Sizeof(cc.Entry.name),
		gc.Name)
	//TODO: cc.Entry._type = gc.Type
	cc.Entry.connect_timeout = gc.ConnectTimeout

	cc.Entry.load_assignment.lb_policy = LBPolicyToC[gc.LoadAssignment.LBPolicy]
	for _, v := range gc.LoadAssignment.Endpoints {
		ce := v.ToClang()	// never failed
		cc.Endpoints = append(cc.Endpoints, *ce)
	}

	Memcpy(unsafe.Pointer(&cc.Entry.circuit_breaker),
		unsafe.Pointer(&gc.CircuitBreaker),
		unsafe.Sizeof(cc.Entry.circuit_breaker))

	return cc
}
