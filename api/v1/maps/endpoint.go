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

import (
	"github.com/cilium/ebpf"
	"openeuler.io/mesh/api/v1/types"
	"openeuler.io/mesh/pkg/bpf"
	"unsafe"
)

func endpointToGolang(ep *types.Endpoint, cep *types.CEndpoint) {
	memcpy(unsafe.Pointer(ep),
		unsafe.Pointer(&cep.Entry),
		unsafe.Sizeof(cep.Entry))
}

func endpointToClang(ep *types.Endpoint) *types.CEndpoint {
	cep := &types.CEndpoint{}
	memcpy(unsafe.Pointer(&cep.Entry),
		unsafe.Pointer(ep),
		unsafe.Sizeof(cep.Entry))

	return cep
}

func EndpointLookup(ep *types.Endpoint, key *types.MapKey) error {
	cep := &types.CEndpoint{}
	err := bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Endpoint.
		Lookup(key, cep.Entry)

	if err == nil {
		endpointToGolang(ep, cep)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *ep)

	return err
}

func EndpointUpdate(ep *types.Endpoint, key *types.MapKey) error {
	log.Debugf("Update [%#v], [%#v]", *key, *ep)
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Endpoint.
		Update(key, &endpointToClang(ep).Entry, ebpf.UpdateAny)
}

func EndpointDelete(ep *types.Endpoint, key *types.MapKey) error {
	log.Debugf("Delete [%#v], [%#v]", *key, *ep)
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Endpoint.
		Delete(key)
}

func loadbalanceToGolang(lb *types.Loadbalance, clb *types.CLoadbalance) {
	memcpy(unsafe.Pointer(lb),
		unsafe.Pointer(&clb.Entry),
		unsafe.Sizeof(clb.Entry))
}

func loadbalanceToClang(lb *types.Loadbalance) *types.CLoadbalance {
	clb := &types.CLoadbalance{}
	memcpy(unsafe.Pointer(&clb.Entry),
		unsafe.Pointer(lb),
		unsafe.Sizeof(clb.Entry))

	return clb
}

func LoadbalanceLookup(lb *types.Loadbalance, key *types.MapKey) error {
	clb := &types.CLoadbalance{}
	err := bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Loadbalance.
		Lookup(key, clb.Entry)

	if err == nil {
		loadbalanceToGolang(lb, clb)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *lb)

	return err
}

func LoadbalanceUpdate(lb *types.Loadbalance, key *types.MapKey) error {
	log.Debugf("Update [%#v], [%#v]", *key, *lb)
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Loadbalance.
		Update(key, &loadbalanceToClang(lb).Entry, ebpf.UpdateAny)
}

func LoadbalanceDelete(lb *types.Loadbalance, key *types.MapKey) error {
	log.Debugf("Delete [%#v], [%#v]", *key, *lb)
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Loadbalance.
		Delete(key)
}
