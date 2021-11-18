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
// #include "listener.h"
import "C"
import (
	"github.com/cilium/ebpf"
	"openeuler.io/mesh/pkg/bpf"
	"unsafe"
)

// CListener = C.listener_t
type CListener struct {
	Entry	C.listener_t
	Cluster	CCluster
}

func (cl *CListener) Lookup(key *GoAddress) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Listener.
		Lookup(key, &cl.Entry)
}

func (cl *CListener) Update(key *GoAddress) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Listener.
		Update(key, &cl.Entry, ebpf.UpdateAny)
}

func (cl *CListener) Delete(key *GoAddress) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Listener.
		Delete(key)
}

type GoListener struct {
	Name	string	`json:"name"`
	Type	string	`json:"type"`
	Address	GoAddress	`json:"address"`
	Cluster	GoCluster	`json:"cluster,omitempty"`
}

func (cl *CListener) ToGolang() *GoListener {
	gl := &GoListener{}
	gl.Name = C.GoString( (*C.char)(unsafe.Pointer(cl.Entry.name)) )
	gl.Type = cl.Entry._type

	Memcpy(unsafe.Pointer(&gl.Address),
		unsafe.Pointer(&cl.Entry.address),
		unsafe.Sizeof(gl.Address))

	gl.Cluster = *cl.Cluster.ToGolang()
	return gl
}

func (gl *GoListener) ToClang() *CListener {
	cl := &CListener{}
	StrcpyToC(unsafe.Pointer(&cl.Entry.name),
		unsafe.Sizeof(cl.Entry.name),
		gl.Name)
	cl.Entry._type = gl.Type

	Memcpy(unsafe.Pointer(&cl.Entry.address),
		unsafe.Pointer(&gl.Address),
		unsafe.Sizeof(cl.Entry.address))

	cl.Cluster = *gl.Cluster.ToClang()
	return cl
}
