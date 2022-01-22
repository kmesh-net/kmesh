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

package types

// #cgo CFLAGS: -I../../../bpf/include
// #include "listener_type.h"
import "C"
import (
	"github.com/cilium/ebpf"
	"openeuler.io/mesh/pkg/bpf"
	"unsafe"
)

// cListener = C.listener_t
type cListener struct {
	entry C.listener_t
}

type Listener struct {
	MapKey MapKey
	//Name	string	`json:"name"`
	Type    uint16  `json:"type"`
	State   uint16  `json:"state"`
	Address Address `json:"address"`
}

func (l *Listener) toGolang(cl *cListener) {
	memcpy(unsafe.Pointer(l),
		unsafe.Pointer(&cl.entry),
		unsafe.Sizeof(cl.entry))
}

func (l *Listener) toClang() *cListener {
	cl := &cListener{}
	memcpy(unsafe.Pointer(&cl.entry),
		unsafe.Pointer(l),
		unsafe.Sizeof(cl.entry))

	return cl
}

func (l *Listener) Lookup(key *Address) error {
	cl := &cListener{}
	err := bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Listener.
		Lookup(key, cl.entry)

	if err == nil {
		l.toGolang(cl)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *l)

	return err
}

func (l *Listener) Update(key *Address) error {
	log.Debugf("Update [%#v], [%#v]", *key, *l)
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Listener.
		Update(key, &l.toClang().entry, ebpf.UpdateAny)
}

func (l *Listener) Delete(key *Address) error {
	log.Debugf("Delete [%#v], [%#v]", *key, *l)
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Listener.
		Delete(key)
}
