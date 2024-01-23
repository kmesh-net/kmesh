/*
 * Copyright 2023 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

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

	core_v2 "kmesh.net/kmesh/api/v2/core"
	listener_v2 "kmesh.net/kmesh/api/v2/listener"
	"kmesh.net/kmesh/pkg/logger"
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
