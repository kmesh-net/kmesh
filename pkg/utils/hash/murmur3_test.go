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

package hash

import (
	"fmt"
	"testing"
)

func TestHash128_DifferentSeeds(t *testing.T) {
	input := []byte("test input")

	h1_seed0, h2_seed0 := Hash128(input, 0)
	h1_seed1, h2_seed1 := Hash128(input, 1)

	if (h1_seed0 == h1_seed1) && (h2_seed0 == h2_seed1) {
		t.Errorf("Different seeds produced same hash: (%d, %d)", h1_seed0, h2_seed0)
	}
}

func TestHash128_TailCases(t *testing.T) {
	seed := uint32(0)
	expected := []struct {
		h1 uint64
		h2 uint64
	}{
		{5467490433528156583, 9782763267945859290},
		{7365496233626374817, 4509812671008863076},
		{12573662846152529695, 7461964302156406396},
		{9835107160104111132, 10470535468262275298},
		{361946897411615576, 17996517921075712664},
		{16846892524183029451, 13280208045458370287},
		{4578864950277010102, 12632592208615550477},
		{14800598385962173449, 5191467188622709264},
		{17098945199622310944, 7563156776339729347},
		{156324995665638904, 17134821293174869613},
		{12380062088919656819, 16542457023974195919},
		{1082955700493610954, 6369146761905933195},
		{14036760400416503843, 5952865372487413191},
		{11535319495064235047, 7524327669449282404},
		{14149555822753749515, 10930268772313463049},
		{8065951757315601820, 11099135757563705731},
	}

	baseData := []byte("0123456789abcdef")
	tailData := []byte("extra tail bytes")

	for tailLen, want := range expected {
		t.Run(fmt.Sprintf("tail_len_%d", tailLen), func(t *testing.T) {
			input := append([]byte{}, baseData...)
			input = append(input, tailData[:tailLen]...)

			h1, h2 := Hash128(input, seed)
			if h1 != want.h1 || h2 != want.h2 {
				t.Errorf("Hash128 with tail length %d = (%d, %d), want (%d, %d)",
					tailLen, h1, h2, want.h1, want.h2)
			}
		})
	}
}

func TestHash128_LargeInput(t *testing.T) {
	// Test with large input to ensure no issues with memory
	largeInput := make([]byte, 10000)
	for i := range largeInput {
		largeInput[i] = byte(i % 256)
	}

	h1, h2 := Hash128(largeInput, 0)
	if h1 == 0 && h2 == 0 {
		t.Errorf("Hash128 with large input returned (0, 0)")
	}
}

func TestRotl64(t *testing.T) {
	tests := []struct {
		name     string
		x        uint64
		r        int8
		expected uint64
	}{
		{
			name:     "rotate 0",
			x:        0x123456789abcdef0,
			r:        0,
			expected: 0x123456789abcdef0,
		},
		{
			name:     "rotate 1",
			x:        0x123456789abcdef0,
			r:        1,
			expected: 0x2468acf13579bde0,
		},
		{
			name:     "rotate 32",
			x:        0x123456789abcdef0,
			r:        32,
			expected: 0x9abcdef012345678,
		},
		{
			name:     "rotate 63",
			x:        0x123456789abcdef0,
			r:        63,
			expected: 0x091a2b3c4d5e6f78,
		},
		{
			name:     "all ones",
			x:        0xffffffffffffffff,
			r:        31,
			expected: 0xffffffffffffffff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rotl64(tt.x, tt.r)
			if result != tt.expected {
				t.Errorf("rotl64(0x%x, %d) = 0x%x, want 0x%x", tt.x, tt.r, result, tt.expected)
			}
		})
	}
}

func TestFmix64(t *testing.T) {
	tests := []struct {
		name     string
		input    uint64
		expected uint64
	}{
		{
			name:     "zero",
			input:    0,
			expected: 0,
		},
		{
			name:     "max value",
			input:    0xffffffffffffffff,
			expected: 0x64b5720b4b825f21,
		},
		{
			name:     "test value",
			input:    0x123456789abcdef0,
			expected: 0x18b8c062f6f42398,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fmix64(tt.input)
			if result != tt.expected {
				t.Errorf("fmix64(0x%x) = 0x%x, want 0x%x", tt.input, result, tt.expected)
			}
		})
	}
}

func BenchmarkHash128_ExtraLarge(b *testing.B) {
	data := make([]byte, 8192)
	for i := range data {
		data[i] = byte(i)
	}
	seed := uint32(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash128(data, seed)
	}
}

func BenchmarkRotl64(b *testing.B) {
	x := uint64(0x123456789abcdef0)
	r := int8(31)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rotl64(x, r)
	}
}

func BenchmarkFmix64(b *testing.B) {
	k := uint64(0x123456789abcdef0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fmix64(k)
	}
}
