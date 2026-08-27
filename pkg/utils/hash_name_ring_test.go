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
	"math"
	"testing"
)

// fixedHash32 is a hash.Hash32 whose Sum32 always returns a fixed value, so the
// linear-probing loop in Hash() can be driven onto an exact slot deterministically
// (brute-forcing a real FNV32a preimage for 0xFFFFFFFF is infeasible).
type fixedHash32 struct{ v uint32 }

func (f fixedHash32) Write(p []byte) (int, error) { return len(p), nil }
func (f fixedHash32) Sum(b []byte) []byte         { return b }
func (f fixedHash32) Reset()                      {}
func (f fixedHash32) Size() int                   { return 4 }
func (f fixedHash32) BlockSize() int              { return 1 }
func (f fixedHash32) Sum32() uint32               { return f.v }

// TestHash_MaxUint32SlotIsRegistered verifies that when linear probing lands on
// the top slot (math.MaxUint32), Hash() actually records it in numToStr/strToNum
// instead of returning an unregistered id. The old `num < math.MaxUint32` loop
// bound skipped the final slot entirely, so Hash returned MaxUint32 without ever
// writing the maps, breaking the round-trip (NumToStr/StrToNum disagree).
func TestHash_MaxUint32SlotIsRegistered(t *testing.T) {
	h := &HashName{
		numToStr: make(map[uint32]string),
		strToNum: make(map[string]uint32),
		hash:     fixedHash32{v: math.MaxUint32},
	}
	const key = "hits-the-max-slot"

	got := h.Hash(key)
	if got != math.MaxUint32 {
		t.Fatalf("Hash(%q) = %d, want %d", key, got, uint32(math.MaxUint32))
	}
	if h.NumToStr(math.MaxUint32) != key {
		t.Fatalf("NumToStr(MaxUint32) = %q, want %q — top slot was returned but never registered", h.NumToStr(math.MaxUint32), key)
	}
	if h.StrToNum(key) != math.MaxUint32 {
		t.Fatalf("StrToNum(%q) = %d, want %d — reverse map never registered", key, h.StrToNum(key), uint32(math.MaxUint32))
	}
}
