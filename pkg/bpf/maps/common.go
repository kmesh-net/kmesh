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

// #include <string.h>
import "C"
import (
	"fmt"
	"unsafe"
)

// GoMapKey = C.map_key_t
type GoMapKey struct {
	NameID	uint32
	Index	uint32
}

// GoAddress = C.address_t
type GoAddress struct {
	Protocol	uint32	`json:"protocol"`
	Port		uint32	`json:"port"`
	IPv4		uint32	`json:"ipv4,omitempty"`
	IPv6		[4]uint32	`json:"ipv6,omitempty"`
}

func ByteToString() {
	b := [16]byte{'h', 'e', 'l', 'l', 'o', '0'}
	fmt.Println(string(b[:]))
}

func StringToByte() {
	b := [16]byte{}
	s := "hello"
	copy(b[:], s[:])
}

func Memcpy(dst, src unsafe.Pointer, len uintptr) {
	C.memcpy(dst, src, C.ulong(len))
}

func StrcpyToC(cStr unsafe.Pointer, len uintptr, goStr string) {
	dst := (*C.char)(cStr)
	src := C.CString(goStr)
	defer C.free(unsafe.Pointer(src))

	if len > unsafe.Sizeof(goStr) {
		len = unsafe.Sizeof(goStr)
	}
	C.strncpy(dst, src, C.ulong(len))
	dst[len] = 0
}

// TODO: turn string to uint32