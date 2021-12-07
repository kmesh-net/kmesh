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
// #include <stdlib.h>
import "C"
import (
	"hash/fnv"
	"math"
	"openeuler.io/mesh/pkg/logger"
	"unsafe"
)

const (
	pkgSubsys = "maps"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
)

// GoMapKey = C.map_key_t
type GoMapKey struct {
	NameID	uint32
	Port	uint32
	Index	uint32
}

// GoAddress = C.address_t
type GoAddress struct {
	Protocol	uint32	`json:"protocol"`
	Port		uint32	`json:"port"`
	IPv4		uint32	`json:"ipv4,omitempty"`
	IPv6		[4]uint32	`json:"ipv6,omitempty"`
}

var hash = fnv.New32a()

// ConvertMapKey converts a string to a uint32 integer as the key of bpf map
type ConvertMapKey struct {
	numToStr map[uint32]string
}

func NewConvertMapKey() *ConvertMapKey {
	con := &ConvertMapKey{}
	con.numToStr = make(map[uint32]string)
	return con
}

func (con *ConvertMapKey) StrToNum(str string) uint32 {
	var num uint32

	hash.Reset()
	hash.Write([]byte(str))

	// Using linear probing to solve hash conflicts
	for num = hash.Sum32(); num < math.MaxUint32; num++ {
		if con.numToStr[num] == "" {
			con.numToStr[num] = str
			break
		} else if con.numToStr[num] == str {
			break
		}
	}

	return num
}

func (con *ConvertMapKey) NumToStr(num uint32) string {
	return con.numToStr[num]
}

func (con *ConvertMapKey) Delete(str string) {
	con.numToStr[con.StrToNum(str)] = ""
}

func Memcpy(dst, src unsafe.Pointer, len uintptr) {
	C.memcpy(dst, src, C.size_t(len))
}

func StrcpyToC(cStr unsafe.Pointer, len uintptr, goStr string) {
	C.memset(cStr, 0, C.size_t(len))

	dst := (*C.char)(cStr)
	src := C.CString(goStr)
	defer C.free(unsafe.Pointer(src))

	if len > unsafe.Sizeof(goStr) {
		len = unsafe.Sizeof(goStr)
	}
	C.strncpy(dst, src, C.size_t(len))
}
