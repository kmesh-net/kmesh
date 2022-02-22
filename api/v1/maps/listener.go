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

func listenerToGolang(l *api_v1.Listener, cl *api_v1.CListener) {
	memcpy(unsafe.Pointer(l),
		unsafe.Pointer(&cl.Entry),
		unsafe.Sizeof(cl.Entry))
}

func listenerToClang(l *api_v1.Listener) *api_v1.CListener {
	cl := &api_v1.CListener{}
	memcpy(unsafe.Pointer(&cl.Entry),
		unsafe.Pointer(l),
		unsafe.Sizeof(cl.Entry))

	return cl
}

func ListenerLookup(l *api_v1.Listener, key *api_v1.Address) error {
	cl := &api_v1.CListener{}
	err := bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Listener.
		Lookup(key, cl.Entry)

	if err == nil {
		listenerToGolang(l, cl)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *l)

	return err
}

func ListenerUpdate(l *api_v1.Listener, key *api_v1.Address) error {
	log.Debugf("Update [%#v], [%#v]", *key, *l)
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Listener.
		Update(key, &listenerToClang(l).Entry, ebpf.UpdateAny)
}

func ListenerDelete(l *api_v1.Listener, key *api_v1.Address) error {
	log.Debugf("Delete [%#v], [%#v]", *key, *l)
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Listener.
		Delete(key)
}
