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
// #include "core/address.pb-c.h"
// #include <stdlib.h>
import "C"
import (
	"fmt"
	"google.golang.org/protobuf/proto"
	core_v2 "openeuler.io/mesh/api/v2/core"
	"unsafe"
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