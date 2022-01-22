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

// #include <string.h>
// #include <stdlib.h>
import "C"
import (
	"openeuler.io/mesh/pkg/logger"
	"unsafe"
)

const (
	pkgSubsys = "api/types"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
)

// MapKey = C.map_key_t
type MapKey struct {
	NameID	uint32
	Port	uint32
	Index	uint32
}

// Address = C.address_t
type Address struct {
	Protocol	uint32	`json:"protocol"`
	Port		uint32	`json:"port"`
	IPv4		uint32	`json:"ipv4,omitempty"`
	IPv6		[4]uint32	`json:"ipv6,omitempty"`
}

func memcpy(dst, src unsafe.Pointer, len uintptr) {
	C.memcpy(dst, src, C.size_t(len))
}

func strcpyToC(cStr unsafe.Pointer, len uintptr, goStr string) {
	C.memset(cStr, 0, C.size_t(len))

	dst := (*C.char)(cStr)
	src := C.CString(goStr)
	defer C.free(unsafe.Pointer(src))

	if len > unsafe.Sizeof(goStr) {
		len = unsafe.Sizeof(goStr)
	}
	C.strncpy(dst, src, C.size_t(len))
}
