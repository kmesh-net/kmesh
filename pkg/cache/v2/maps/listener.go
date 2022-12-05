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
 * Create: 2022-02-28
 */

package maps

// #cgo pkg-config: api-v2-c
// #include "deserialization_to_bpf_map.h"
// #include "listener/listener.pb-c.h"
import "C"
import (
	"fmt"
	"unsafe"

	"google.golang.org/protobuf/proto"
	core_v2 "openeuler.io/mesh/api/v2/core"
	listener_v2 "openeuler.io/mesh/api/v2/listener"
	"openeuler.io/mesh/pkg/logger"
)

var (
	log = logger.NewLoggerField("cache/v2/maps")
)

func listenerToGolang(goMsg *listener_v2.Listener, cMsg *C.Listener__Listener) error {
	buf := make([]byte, C.listener__listener__get_packed_size(cMsg))

	C.listener__listener__pack(cMsg, convertToPack(buf))
	if err := proto.Unmarshal(buf, goMsg); err != nil {
		return err
	}
	return nil
}

func listenerToClang(goMsg *listener_v2.Listener) (*C.Listener__Listener, error) {
	buf, err := proto.Marshal(goMsg)
	if err != nil {
		return nil, err
	}

	cMsg := C.listener__listener__unpack(nil, C.size_t(len(buf)), convertToPack(buf))
	if cMsg == nil {
		return nil, fmt.Errorf("listener__listener__unpack failed")
	}
	return cMsg, nil
}

func listenerFreeClang(cMsg *C.Listener__Listener) {
	C.listener__listener__free_unpacked(cMsg, nil)
}

func ListenerLookup(key *core_v2.SocketAddress, value *listener_v2.Listener) error {
	var err error

	cKey, err := socketAddressToClang(key)
	if err != nil {
		return fmt.Errorf("ListenerLookup %s", err)
	}
	defer socketAddressFreeClang(cKey)
	
	desc := cKey.base.descriptor
	cKey.base.descriptor = nil
	cMsg := C.deserial_lookup_elem(unsafe.Pointer(cKey), unsafe.Pointer(&C.listener__listener__descriptor))
	cKey.base.descriptor = desc
	if cMsg == nil {
		return fmt.Errorf("ListenerLookup deserial_lookup_elem failed")
	}
	defer C.deserial_free_elem(unsafe.Pointer(cMsg))

	err = listenerToGolang(value, (*C.Listener__Listener)(cMsg))
	log.Debugf("ListenerLookup [%s], [%s]", key.String(), value.String())
	return err
}

func ListenerUpdate(key *core_v2.SocketAddress, value *listener_v2.Listener) error {
	var err error
	log.Debugf("ListenerUpdate [%s], [%s]", key.String(), value.String())

	cKey, err := socketAddressToClang(key)
	if err != nil {
		return fmt.Errorf("ListenerLookup %s", err)
	}
	defer socketAddressFreeClang(cKey)

	cMsg, err := listenerToClang(value)
	if err != nil {
		return fmt.Errorf("ListenerUpdate %s", err)
	}
	defer listenerFreeClang(cMsg)

	testSocketAddress(key, cKey)
	testListener(value, cMsg)

	desc := cKey.base.descriptor
	cKey.base.descriptor = nil
	ret := C.deserial_update_elem(unsafe.Pointer(cKey), unsafe.Pointer(cMsg))
	cKey.base.descriptor = desc
	if ret != 0 {
		return fmt.Errorf("ListenerUpdate deserial_update_elem failed")
	}

	return nil
}

func ListenerDelete(key *core_v2.SocketAddress) error {
	log.Debugf("ListenerDelete [%s]", key.String())

	cKey, err := socketAddressToClang(key)
	if err != nil {
		return fmt.Errorf("ListenerLookup %s", err)
	}
	defer socketAddressFreeClang(cKey)

	desc := cKey.base.descriptor
	cKey.base.descriptor = nil
	ret := C.deserial_delete_elem(unsafe.Pointer(cKey), unsafe.Pointer(&C.listener__listener__descriptor))
	cKey.base.descriptor = desc
	if ret != 0 {
		return fmt.Errorf("ListenerDelete deserial_delete_elem failed")
	}
	return nil
}

func testListener(goMsg *listener_v2.Listener, cMsg *C.Listener__Listener) {
	listener := &listener_v2.Listener{}

	if err := listenerToGolang(listener, cMsg); err != nil {
		log.Errorf("testListenerUpdate listenerToGolang failed")
	}
	if goMsg.String() != listener.String() {
		log.Errorf("testListenerUpdate invalid message")
		log.Errorf("testListenerUpdate [%s]", listener.String())
	}
}
