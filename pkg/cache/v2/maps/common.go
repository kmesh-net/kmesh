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
// #include "core/address.pb-c.h"
// #include <stdlib.h>
import "C"
import (
	"fmt"
	"unsafe"

	"google.golang.org/protobuf/proto"

	core_v2 "kmesh.net/kmesh/api/v2/core"
)

func convertToPack(buf []byte) *C.uint8_t {
	return (*C.uint8_t)(unsafe.Pointer(&buf[0]))
}

func socketAddressToGolang(goMsg *core_v2.SocketAddress, cMsg *C.Core__SocketAddress) error {
	buf := make([]byte, C.core__socket_address__get_packed_size(cMsg))

	C.core__socket_address__pack(cMsg, convertToPack(buf))
	if err := proto.Unmarshal(buf, goMsg); err != nil {
		return err
	}
	return nil
}

func socketAddressToClang(goMsg *core_v2.SocketAddress) (*C.Core__SocketAddress, error) {
	buf, err := proto.Marshal(goMsg)
	if err != nil {
		return nil, err
	}

	cMsg := C.core__socket_address__unpack(nil, C.size_t(len(buf)), convertToPack(buf))
	if cMsg == nil {
		return nil, fmt.Errorf("core__socket_address__unpack failed")
	}
	return cMsg, nil
}

func socketAddressFreeClang(cMsg *C.Core__SocketAddress) {
	C.core__socket_address__free_unpacked(cMsg, nil)
}

func testSocketAddress(goMsg *core_v2.SocketAddress, cMsg *C.Core__SocketAddress) {
	msg := &core_v2.SocketAddress{}

	if err := socketAddressToGolang(msg, cMsg); err != nil {
		log.Errorf("testSocketAddress socketAddressToGolang failed")
	}
	if goMsg.String() != msg.String() {
		log.Errorf("testSocketAddress invalid message")
		log.Errorf("testSocketAddress [%s]", msg.String())
	}
}

func stringToGolang(cMsg *C.char) string {
	return C.GoString(cMsg)
}

func stringToClang(goMsg string) *C.char {
	return C.CString(goMsg)
}

func stringFreeClang(cMsg *C.char) {
	if cMsg != nil {
		C.free(unsafe.Pointer(cMsg))
	}
}

func testString(goMsg string, cMsg *C.char) {
	msg := stringToGolang(cMsg)
	if goMsg != msg {
		log.Errorf("testString invalid message")
		log.Errorf("testString [%s]", msg)
	}
}
