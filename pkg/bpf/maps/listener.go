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
)

// CListener = C.listener_t
type CListener struct {
	Entry	C.listener_t
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

}

func (cl *CListener) ToGolang() *GoListener {
	return nil
}

func (gl *GoListener) ToClang() *CListener {
	return nil
}
