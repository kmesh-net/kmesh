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

// #cgo CFLAGS: -I../../../bpf/include
// #include "endpoint_type.h"
import "C"
import (
	"github.com/cilium/ebpf"
	"openeuler.io/mesh/pkg/bpf"
	"unsafe"
)

// CEndpoint = C.endpoint_t
type CEndpoint struct {
	Entry	C.endpoint_t
}

func (ce *CEndpoint) Lookup(key *GoMapKey) error {
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Endpoint.
		Lookup(key, &ce.Entry)
}

func (ce *CEndpoint) Update(key *GoMapKey) error {
	log.Debugf("Update %#v", *key)
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Endpoint.
		Update(key, &ce.Entry, ebpf.UpdateAny)
}

func (ce *CEndpoint) Delete(key *GoMapKey) error {
	log.Debugf("Delete %#v", *key)
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Endpoint.
		Delete(key)
}

type GoEndpoint struct {
	Address		GoAddress	`json:"address"`
	LBPriority	uint16	`json:"lb_priority"`
	LBWeight	uint16	`json:"lb_weight"`
}

func (ce *CEndpoint) ToGolang() *GoEndpoint {
	ge := &GoEndpoint{}
	Memcpy(unsafe.Pointer(ge),
		unsafe.Pointer(&ce.Entry),
		unsafe.Sizeof(ce.Entry))

	return ge
}

func (ge *GoEndpoint) ToClang() *CEndpoint {
	ce := &CEndpoint{}
	Memcpy(unsafe.Pointer(&ce.Entry),
		unsafe.Pointer(ge),
		unsafe.Sizeof(ce.Entry))

	log.Debugf("%#v", *ge)
	return ce
}

// CLoadbalance = C.loadbalance_t
type CLoadbalance struct {
	Entry	C.loadbalance_t
}

func (clb *CLoadbalance) Lookup(key *GoMapKey) error {
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Loadbalance.
		Lookup(key, &clb.Entry)
}

func (clb *CLoadbalance) Update(key *GoMapKey) error {
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Loadbalance.
		Update(key, &clb.Entry, ebpf.UpdateAny)
}

func (clb *CLoadbalance) Delete(key *GoMapKey) error {
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Loadbalance.
		Delete(key)
}

type GoLoadbalance struct {
	MapKey	GoMapKey	`json:"map_key"`
	LBConnNum	uint32	`json:"lb_conn_num"`
}

func (clb *CLoadbalance) ToGolang() *GoLoadbalance {
	glb := &GoLoadbalance{}
	Memcpy(unsafe.Pointer(glb),
		unsafe.Pointer(&clb.Entry),
		unsafe.Sizeof(clb.Entry))

	return glb
}

func (glb *GoLoadbalance) ToClang() *CLoadbalance {
	clb := &CLoadbalance{}
	Memcpy(unsafe.Pointer(&clb.Entry),
		unsafe.Pointer(glb),
		unsafe.Sizeof(clb.Entry))

	log.Debugf("%#v", *glb)
	return clb
}
