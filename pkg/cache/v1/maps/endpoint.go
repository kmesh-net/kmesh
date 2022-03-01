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

func endpointToGolang(goMsg *api_v1.Endpoint, cMsg *api_v1.CEndpoint) {
	memcpy(unsafe.Pointer(goMsg),
		unsafe.Pointer(&cMsg.Entry),
		unsafe.Sizeof(cMsg.Entry))
}

func endpointToClang(goMsg *api_v1.Endpoint) *api_v1.CEndpoint {
	cMsg := &api_v1.CEndpoint{}
	memcpy(unsafe.Pointer(&cMsg.Entry),
		unsafe.Pointer(goMsg),
		unsafe.Sizeof(cMsg.Entry))

	return cMsg
}

func EndpointLookup(key *api_v1.MapKey, value *api_v1.Endpoint) error {
	cMsg := &api_v1.CEndpoint{}
	err := bpf.Obj.Slb.ClusterObjects.ClusterMaps.Endpoint.
		Lookup(key, cMsg.Entry)

	if err == nil {
		endpointToGolang(value, cMsg)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *value)

	return err
}

func EndpointUpdate(key *api_v1.MapKey, value *api_v1.Endpoint) error {
	log.Debugf("Update [%#v], [%#v]", *key, *value)
	return bpf.Obj.Slb.ClusterObjects.ClusterMaps.Endpoint.
		Update(key, &endpointToClang(value).Entry, ebpf.UpdateAny)
}

func EndpointDelete(key *api_v1.MapKey) error {
	log.Debugf("Delete [%#v]", *key)
	return bpf.Obj.Slb.ClusterObjects.ClusterMaps.Endpoint.
		Delete(key)
}

func loadbalanceToGolang(goMsg *api_v1.Loadbalance, cMsg *api_v1.CLoadbalance) {
	memcpy(unsafe.Pointer(goMsg),
		unsafe.Pointer(&cMsg.Entry),
		unsafe.Sizeof(cMsg.Entry))
}

func loadbalanceToClang(goMsg *api_v1.Loadbalance) *api_v1.CLoadbalance {
	cMsg := &api_v1.CLoadbalance{}
	memcpy(unsafe.Pointer(&cMsg.Entry),
		unsafe.Pointer(goMsg),
		unsafe.Sizeof(cMsg.Entry))

	return cMsg
}

func LoadbalanceLookup(key *api_v1.MapKey, value *api_v1.Loadbalance) error {
	cMsg := &api_v1.CLoadbalance{}
	err := bpf.Obj.Slb.ClusterObjects.ClusterMaps.Loadbalance.
		Lookup(key, cMsg.Entry)

	if err == nil {
		loadbalanceToGolang(value, cMsg)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *value)

	return err
}

func LoadbalanceUpdate(key *api_v1.MapKey, value *api_v1.Loadbalance) error {
	log.Debugf("Update [%#v], [%#v]", *key, *value)
	return bpf.Obj.Slb.ClusterObjects.ClusterMaps.Loadbalance.
		Update(key, &loadbalanceToClang(value).Entry, ebpf.UpdateAny)
}

func LoadbalanceDelete(key *api_v1.MapKey) error {
	log.Debugf("Delete [%#v]", *key)
	return bpf.Obj.Slb.ClusterObjects.ClusterMaps.Loadbalance.
		Delete(key)
}
