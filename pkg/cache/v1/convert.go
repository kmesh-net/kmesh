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

package cache_v1

import (
	"hash/fnv"
	"math"
	"openeuler.io/mesh/pkg/logger"
)

const (
	pkgSubsys = "api"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)

	hash = fnv.New32a()
)

// ConvertName converts a string to a uint32 integer as the key of bpf map
type ConvertName struct {
	numToStr map[uint32]string
}

func NewConvertName() *ConvertName {
	con := &ConvertName{}
	con.numToStr = make(map[uint32]string)
	return con
}

func (con *ConvertName) StrToNum(str string) uint32 {
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

func (con *ConvertName) NumToStr(num uint32) string {
	return con.numToStr[num]
}

func (con *ConvertName) Delete(str string) {
	delete(con.numToStr, con.StrToNum(str))
}
