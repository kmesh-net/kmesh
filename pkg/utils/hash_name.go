/*
 * Copyright The Kmesh Authors.
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

package utils

import (
	"fmt"
	"hash"
	"hash/fnv"
	"math"
	"os"

	"sigs.k8s.io/yaml"
)

var (
	persistPath = "/mnt/hash_name.yaml"
)

// HashName converts a string to a uint32 integer as the key of bpf map
type HashName struct {
	numToStr map[uint32]string
	strToNum map[string]uint32
	hash     hash.Hash32
}

func NewHashName() *HashName {
	hashName := &HashName{
		strToNum: make(map[string]uint32),
		hash:     fnv.New32a(),
	}
	// if read failed, initialize with an empty map
	if err := hashName.readFromPersistFile(); err != nil {
		hashName.numToStr = make(map[uint32]string)
	} else {
		hashName.numToStr = make(map[uint32]string, len(hashName.strToNum))
		for str, num := range hashName.strToNum {
			hashName.numToStr[num] = str
		}
	}
	return hashName
}

func (h *HashName) readFromPersistFile() error {
	data, err := os.ReadFile(persistPath)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, &h.strToNum)
}

func (h *HashName) flush() error {
	// We only need to flush strToNum here, since we can generate numToStr from it.
	if len(h.strToNum) == 0 {
		return os.WriteFile(persistPath, nil, 0644)
	}

	yaml, err := yaml.Marshal(h.strToNum)
	if err != nil {
		return err
	}

	return os.WriteFile(persistPath, yaml, 0644)
}

// flushDelta is similar to flush, but it appends new item instead of flush all data
func (h *HashName) flushDelta(str string, num uint32) error {
	f, err := os.OpenFile(persistPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	data := fmt.Sprintf("%s: %d\n", str, num)
	_, err = f.WriteString(data)
	return err
}

func (h *HashName) Hash(str string) uint32 {
	var num uint32

	if num, exists := h.strToNum[str]; exists {
		return num
	}

	h.hash.Reset()
	h.hash.Write([]byte(str))
	// Using linear probing to solve hash conflicts
	for num = h.hash.Sum32(); num < math.MaxUint32; num++ {
		// Create a new item if we find an empty slot
		if _, exists := h.numToStr[num]; !exists {
			h.numToStr[num] = str
			h.strToNum[str] = num
			// Create a new item here, should flush
			if err := h.flushDelta(str, num); err != nil {
				log.Errorf("error flushing when calling Hash: %v", err)
			}
			break
		}
		// It's a ring
		if num == math.MaxUint32 {
			num = 0
		}
	}

	return num
}

func (h *HashName) NumToStr(num uint32) string {
	return h.numToStr[num]
}

func (h *HashName) StrToNum(str string) uint32 {
	return h.strToNum[str]
}

func (h *HashName) GetStrToNum() map[string]uint32 {
	return h.strToNum
}

func (h *HashName) Delete(str string) {
	// only when the num exists, we do the logic
	if num, exists := h.strToNum[str]; exists {
		delete(h.numToStr, num)
		delete(h.strToNum, str)
		// delete an old item here, should flush
		if err := h.flush(); err != nil {
			log.Errorf("error flushing when calling Delete: %v", err)
		}
	}
}

// Should only be used by test
func (h *HashName) Reset() {
	os.Remove(persistPath)
}
