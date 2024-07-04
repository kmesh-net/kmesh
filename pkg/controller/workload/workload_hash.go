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
 */

package workload

import (
	"encoding/json"
	"hash/fnv"
	"math"
	"os"
)

var (
	hash = fnv.New32a()
)

const (
	persistPath = "/mnt/workload_hash_name.json"
)

// HashName converts a string to a uint32 integer as the key of bpf map
type HashName struct {
	numToStr map[uint32]string
	strToNum map[string]uint32
}

func NewHashName() *HashName {
	hashName := &HashName{}
	// if read failed, initialize with an empty map
	if err := hashName.readFromPersistFile(); err != nil {
		log.Errorf("error reading persist file: %v", err)
		hashName.numToStr = make(map[uint32]string)
		hashName.strToNum = make(map[string]uint32)
	} else {
		hashName.strToNum = make(map[string]uint32, len(hashName.numToStr))
		for num, str := range hashName.numToStr {
			hashName.strToNum[str] = num
		}
	}
	return hashName
}

func (h *HashName) readFromPersistFile() error {
	data, err := os.ReadFile(persistPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &h.numToStr)
}

func (h *HashName) flush() error {
	// We only need to flush numToStr here, since we can generate strToNum from it.
	json, err := json.Marshal(h.numToStr)
	if err != nil {
		return err
	}

	return os.WriteFile(persistPath, json, 0644)
}

func (h *HashName) StrToNum(str string) uint32 {
	var num uint32

	hash.Reset()
	hash.Write([]byte(str))

	if num, exits := h.strToNum[str]; exits {
		return num
	}

	// Using linear probing to solve hash conflicts
	for num = hash.Sum32(); num < math.MaxUint32; num++ {
		// Create a new item if we find an empty slot
		if _, exists := h.numToStr[num]; !exists {
			h.numToStr[num] = str
			h.strToNum[str] = num
			// Create a new item here, should flush
			if err := h.flush(); err != nil {
				log.Errorf("error flushing when calling StrToNum: %v", err)
			}
			break
		}
	}

	return num
}

func (h *HashName) NumToStr(num uint32) string {
	return h.numToStr[num]
}

func (h *HashName) Delete(str string) {
	// only when the num exists, we do the logic
	if num, exits := h.strToNum[str]; exits {
		delete(h.numToStr, num)
		delete(h.strToNum, str)
		// delete an old item here, should flush
		if err := h.flush(); err != nil {
			log.Errorf("error flushing when calling Delete: %v", err)
		}
	}
}
