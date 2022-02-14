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

// HashName converts a string to a uint32 integer as the key of bpf map
type HashName struct {
	numToStr map[uint32]string
}

func NewHashName() *HashName {
	con := &HashName{}
	con.numToStr = make(map[uint32]string)
	return con
}

func (h *HashName) StrToNum(str string) uint32 {
	var num uint32

	hash.Reset()
	hash.Write([]byte(str))

	// Using linear probing to solve hash conflicts
	for num = hash.Sum32(); num < math.MaxUint32; num++ {
		if h.numToStr[num] == "" {
			h.numToStr[num] = str
			break
		} else if h.numToStr[num] == str {
			break
		}
	}

	return num
}

func (h *HashName) NumToStr(num uint32) string {
	return h.numToStr[num]
}

func (h *HashName) Delete(str string) {
	delete(h.numToStr, h.StrToNum(str))
}
