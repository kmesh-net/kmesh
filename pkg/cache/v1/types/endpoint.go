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

// #cgo CFLAGS: -I../../../../bpf/include
// #include "endpoint_type.h"
import "C"
import (
	"github.com/cilium/ebpf"
	"openeuler.io/mesh/pkg/bpf"
	"unsafe"
)

// cEndpoint = C.endpoint_t
type cEndpoint struct {
	entry C.endpoint_t
}

type Endpoint struct {
	Address    Address `json:"address"`
	LBPriority uint16  `json:"lb_priority"`
	LBWeight   uint16  `json:"lb_weight"`
}

func (ep *Endpoint) toGolang(cep *cEndpoint) {
	memcpy(unsafe.Pointer(ep),
		unsafe.Pointer(&cep.entry),
		unsafe.Sizeof(cep.entry))
}

func (ep *Endpoint) toClang() *cEndpoint {
	cep := &cEndpoint{}
	memcpy(unsafe.Pointer(&cep.entry),
		unsafe.Pointer(ep),
		unsafe.Sizeof(cep.entry))

	return cep
}

func (ep *Endpoint) Lookup(key *MapKey) error {
	cep := &cEndpoint{}
	err := bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Endpoint.
		Lookup(key, cep.entry)

	if err == nil {
		ep.toGolang(cep)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *ep)

	return err
}

func (ep *Endpoint) Update(key *MapKey) error {
	log.Debugf("Update [%#v], [%#v]", *key, *ep)
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Endpoint.
		Update(key, &ep.toClang().entry, ebpf.UpdateAny)
}

func (ep *Endpoint) Delete(key *MapKey) error {
	log.Debugf("Delete [%#v], [%#v]", *key, *ep)
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Endpoint.
		Delete(key)
}

// cLoadbalance = C.loadbalance_t
type cLoadbalance struct {
	entry C.loadbalance_t
}

type Loadbalance struct {
	MapKey    MapKey `json:"map_key"`
	LBConnNum uint32 `json:"lb_conn_num"`
}

func (lb *Loadbalance) toGolang(clb *cLoadbalance) {
	memcpy(unsafe.Pointer(lb),
		unsafe.Pointer(&clb.entry),
		unsafe.Sizeof(clb.entry))
}

func (lb *Loadbalance) toClang() *cLoadbalance {
	clb := &cLoadbalance{}
	memcpy(unsafe.Pointer(&clb.entry),
		unsafe.Pointer(lb),
		unsafe.Sizeof(clb.entry))

	return clb
}

func (lb *Loadbalance) Lookup(key *MapKey) error {
	clb := &cLoadbalance{}
	err := bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Loadbalance.
		Lookup(key, clb.entry)

	if err == nil {
		lb.toGolang(clb)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *lb)

	return err
}

func (lb *Loadbalance) Update(key *MapKey) error {
	log.Debugf("Update [%#v], [%#v]", *key, *lb)
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Loadbalance.
		Update(key, &lb.toClang().entry, ebpf.UpdateAny)
}

func (lb *Loadbalance) Delete(key *MapKey) error {
	log.Debugf("Delete [%#v], [%#v]", *key, *lb)
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Loadbalance.
		Delete(key)
}
