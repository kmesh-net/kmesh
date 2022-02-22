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

func clusterToGolang(cl *api_v1.Cluster, ccl *api_v1.CCluster) {
	memcpy(unsafe.Pointer(cl),
		unsafe.Pointer(&ccl.Entry),
		unsafe.Sizeof(ccl.Entry))
}

func clusterToClang(cl *api_v1.Cluster) *api_v1.CCluster {
	ccl := &api_v1.CCluster{}
	memcpy(unsafe.Pointer(&ccl.Entry),
		unsafe.Pointer(cl),
		unsafe.Sizeof(ccl.Entry))

	return ccl
}

func ClusterLookup(cl *api_v1.Cluster, key *api_v1.MapKey) error {
	ccl := &api_v1.CCluster{}
	err := bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Cluster.
		Lookup(key, ccl.Entry)

	if err == nil {
		clusterToGolang(cl, ccl)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *cl)

	return err
}

func ClusterUpdate(cl *api_v1.Cluster, key *api_v1.MapKey) error {
	log.Debugf("Update [%#v], [%#v]", *key, *cl)
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Cluster.
		Update(key, &clusterToClang(cl).Entry, ebpf.UpdateAny)
}

func ClusterDelete(cl *api_v1.Cluster, key *api_v1.MapKey) error {
	log.Debugf("Delete [%#v], [%#v]", *key, *cl)
	return bpf.Obj.SockConn.ClusterObjects.ClusterMaps.Cluster.
		Delete(key)
}
