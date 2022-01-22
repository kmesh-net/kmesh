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

// #cgo CFLAGS: -I../../../bpf/include
// #include "cluster_type.h"
import "C"
import (
	"github.com/cilium/ebpf"
	"openeuler.io/mesh/pkg/bpf"
	"unsafe"
)

// cCluster = C.cluster_t
type cCluster struct {
	entry C.cluster_t
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

func (cl *Cluster) toGolang(ccl *cCluster) {
	memcpy(unsafe.Pointer(cl),
		unsafe.Pointer(&ccl.entry),
		unsafe.Sizeof(ccl.entry))
}

func (cl *Cluster) toClang() *cCluster {
	ccl := &cCluster{}
	memcpy(unsafe.Pointer(&ccl.entry),
		unsafe.Pointer(cl),
		unsafe.Sizeof(ccl.entry))

	return ccl
}

func (cl *Cluster) Lookup(key *MapKey) error {
	ccl := &cCluster{}
	err := bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Cluster.
		Lookup(key, ccl.entry)

	if err == nil {
		cl.toGolang(ccl)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *cl)

	return err
}

func (cl *Cluster) Update(key *MapKey) error {
	log.Debugf("Update [%#v], [%#v]", *key, *cl)
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Cluster.
		Update(key, &cl.toClang().entry, ebpf.UpdateAny)
}

func (cl *Cluster) Delete(key *MapKey) error {
	log.Debugf("Delete [%#v], [%#v]", *key, *cl)
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Cluster.
		Delete(key)
}