/*
 * Copyright 2024 The Kmesh Authors.
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

 * Author: kwb0523
 * Create: 2024-01-08
 */

package workload

import (
	"hash/fnv"
	"math"
)

var (
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
