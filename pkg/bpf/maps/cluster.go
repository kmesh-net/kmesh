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

}

func (cc *CCluster) ToGolang() *GoCluster {
	return nil
}

func (gc *GoCluster) ToClang() *CCluster {
	return nil
}
