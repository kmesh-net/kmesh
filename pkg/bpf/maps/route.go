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
// #include "route.h"
import "C"
import (
	"github.com/cilium/ebpf"
	"openeuler.io/mesh/pkg/bpf"
)

// CRoute = C.route_t
type CRoute struct {
	Entry	C.route_t
}

func (cr *CRoute) Lookup(key *GoMapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Route.
		Lookup(key, &cr.Entry)
}

func (cr *CRoute) Update(key *GoMapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Route.
		Update(key, &cr.Entry, ebpf.UpdateAny)
}

func (cr *CRoute) Delete(key *GoMapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Route.
		Delete(key)
}

type GoRoute struct {

}

func (cr *CRoute) ToGolang() *GoRoute {
	return nil
}

func (gr *GoRoute) ToClang() *CRoute {
	return nil
}

// CVirtualHost = C.virtual_host_t
type CVirtualHost struct {
	Entry	C.virtual_host_t
}

func (cvh *CVirtualHost) Lookup(key *GoMapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.VirtualHost.
		Lookup(key, &cvh.Entry)
}

func (cvh *CVirtualHost) Update(key *GoMapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.VirtualHost.
		Update(key, &cvh.Entry, ebpf.UpdateAny)
}

func (cvh *CVirtualHost) Delete(key *GoMapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.VirtualHost.
		Delete(key)
}

type GoVirtualHost struct {

}

func (cvh *CVirtualHost) ToGolang() *GoVirtualHost {
	return nil
}

func (gvh *GoVirtualHost) ToClang() *CVirtualHost {
	return nil
}
