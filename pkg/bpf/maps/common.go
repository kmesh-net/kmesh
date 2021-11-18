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

import "C"
import "fmt"

// GoMapKey = C.map_key_t
type GoMapKey struct {
	NameID	uint32
	Index	uint32
}

// GoAddress = C.address_t
type GoAddress struct {
	Protocol	uint32
	Port		uint32
	IPv4		uint32
	IPv6		[4]uint32
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

// TODO: turn string to uint32