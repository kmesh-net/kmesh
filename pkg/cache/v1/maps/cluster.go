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

func clusterToGolang(goMsg *api_v1.Cluster, cMsg *api_v1.CCluster) {
	memcpy(unsafe.Pointer(goMsg),
		unsafe.Pointer(&cMsg.Entry),
		unsafe.Sizeof(cMsg.Entry))
}

func clusterToClang(goMsg *api_v1.Cluster) *api_v1.CCluster {
	cMsg := &api_v1.CCluster{}
	memcpy(unsafe.Pointer(&cMsg.Entry),
		unsafe.Pointer(goMsg),
		unsafe.Sizeof(cMsg.Entry))

	return cMsg
}

func ClusterLookup(key *api_v1.MapKey, value *api_v1.Cluster) error {
	cMsg := &api_v1.CCluster{}
	err := bpf.Obj.Slb.ClusterObjects.ClusterMaps.Cluster.
		Lookup(key, cMsg.Entry)

	if err == nil {
		clusterToGolang(value, cMsg)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *value)

	return err
}

func ClusterUpdate(key *api_v1.MapKey, value *api_v1.Cluster) error {
	log.Debugf("Update [%#v], [%#v]", *key, *value)
	return bpf.Obj.Slb.ClusterObjects.ClusterMaps.Cluster.
		Update(key, &clusterToClang(value).Entry, ebpf.UpdateAny)
}

func ClusterDelete(key *api_v1.MapKey) error {
	log.Debugf("Delete [%#v]", *key)
	return bpf.Obj.Slb.ClusterObjects.ClusterMaps.Cluster.
		Delete(key)
}
