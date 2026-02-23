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

	// Test all possible tail lengths (1-15 bytes after 16-byte blocks)
	for i := 1; i <= 15; i++ {
		input := make([]byte, 16+i) // 16 bytes + i tail bytes
		for j := range input {
			input[j] = byte(j)
		}

		h1, h2 := Hash128(input, seed)

		// Test deterministic behavior
		h1_2, h2_2 := Hash128(input, seed)
		if h1 != h1_2 || h2 != h2_2 {
			t.Errorf("Hash128 with tail length %d is not deterministic", i)
		}
	}
}

func TestHash128_LargeInput(t *testing.T) {
	// Test with large input to ensure no issues with memory/chunking
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
			name:     "zero input",
			input:    0,
			expected: 0,
		},
		{
			name:     "all ones",
			input:    0xffffffffffffffff,
			expected: 0x64b5720b4b825f21,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fmix64(tt.input)
			if result != tt.expected {
				t.Errorf("fmix64(0x%x) = 0x%x, want 0x%x",
					tt.input, result, tt.expected)
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
