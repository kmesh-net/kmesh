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
// #include "route.h"
import "C"
import (
	"github.com/cilium/ebpf"
	"openeuler.io/mesh/pkg/bpf"
)

// ClangRoute = C.route_t
type ClangRoute struct {
	Entry	C.route_t
}

func (cr *ClangRoute) Lookup(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Route.
		Lookup(key, &cr.Entry)
}

func (cr *ClangRoute) Update(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Route.
		Update(key, &cr.Entry, ebpf.UpdateAny)
}

func (cr *ClangRoute) Delete(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Route.
		Delete(key)
}

type Route struct {

}

func (cr *ClangRoute) ToGolang() *Route {
	return nil
}

func (r *Route) ToClang() *ClangRoute {
	return nil
}

// ClangVirtualHost = C.virtual_host_t
type ClangVirtualHost struct {
	Entry	C.virtual_host_t
}

func (cvh *ClangVirtualHost) Lookup(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.VirtualHost.
		Lookup(key, &cvh.Entry)
}

func (cvh *ClangVirtualHost) Update(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.VirtualHost.
		Update(key, &cvh.Entry, ebpf.UpdateAny)
}

func (cvh *ClangVirtualHost) Delete(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.VirtualHost.
		Delete(key)
}

type VirtualHost struct {

}

func (cvh *ClangVirtualHost) ToGolang() *VirtualHost {
	return nil
}

func (vh *VirtualHost) ToClang() *ClangVirtualHost {
	return nil
}
