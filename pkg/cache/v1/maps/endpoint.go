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
	api_v1 "openeuler.io/mesh/api/v1"
	"openeuler.io/mesh/pkg/bpf"
	"unsafe"
)

func endpointToGolang(ep *api_v1.Endpoint, cep *api_v1.CEndpoint) {
	memcpy(unsafe.Pointer(ep),
		unsafe.Pointer(&cep.Entry),
		unsafe.Sizeof(cep.Entry))
}

func endpointToClang(ep *api_v1.Endpoint) *api_v1.CEndpoint {
	cep := &api_v1.CEndpoint{}
	memcpy(unsafe.Pointer(&cep.Entry),
		unsafe.Pointer(ep),
		unsafe.Sizeof(cep.Entry))

	return cep
}

func EndpointLookup(ep *api_v1.Endpoint, key *api_v1.MapKey) error {
	cep := &api_v1.CEndpoint{}
	err := bpf.Obj.Slb.ClusterObjects.ClusterMaps.Endpoint.
		Lookup(key, cep.Entry)

	if err == nil {
		endpointToGolang(ep, cep)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *ep)

	return err
}

func EndpointUpdate(ep *api_v1.Endpoint, key *api_v1.MapKey) error {
	log.Debugf("Update [%#v], [%#v]", *key, *ep)
	return bpf.Obj.Slb.ClusterObjects.ClusterMaps.Endpoint.
		Update(key, &endpointToClang(ep).Entry, ebpf.UpdateAny)
}

func EndpointDelete(ep *api_v1.Endpoint, key *api_v1.MapKey) error {
	log.Debugf("Delete [%#v], [%#v]", *key, *ep)
	return bpf.Obj.Slb.ClusterObjects.ClusterMaps.Endpoint.
		Delete(key)
}

func loadbalanceToGolang(lb *api_v1.Loadbalance, clb *api_v1.CLoadbalance) {
	memcpy(unsafe.Pointer(lb),
		unsafe.Pointer(&clb.Entry),
		unsafe.Sizeof(clb.Entry))
}

func loadbalanceToClang(lb *api_v1.Loadbalance) *api_v1.CLoadbalance {
	clb := &api_v1.CLoadbalance{}
	memcpy(unsafe.Pointer(&clb.Entry),
		unsafe.Pointer(lb),
		unsafe.Sizeof(clb.Entry))

	return clb
}

func LoadbalanceLookup(lb *api_v1.Loadbalance, key *api_v1.MapKey) error {
	clb := &api_v1.CLoadbalance{}
	err := bpf.Obj.Slb.ClusterObjects.ClusterMaps.Loadbalance.
		Lookup(key, clb.Entry)

	if err == nil {
		loadbalanceToGolang(lb, clb)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *lb)

	return err
}

func LoadbalanceUpdate(lb *api_v1.Loadbalance, key *api_v1.MapKey) error {
	log.Debugf("Update [%#v], [%#v]", *key, *lb)
	return bpf.Obj.Slb.ClusterObjects.ClusterMaps.Loadbalance.
		Update(key, &loadbalanceToClang(lb).Entry, ebpf.UpdateAny)
}

func LoadbalanceDelete(lb *api_v1.Loadbalance, key *api_v1.MapKey) error {
	log.Debugf("Delete [%#v], [%#v]", *key, *lb)
	return bpf.Obj.Slb.ClusterObjects.ClusterMaps.Loadbalance.
		Delete(key)
}
