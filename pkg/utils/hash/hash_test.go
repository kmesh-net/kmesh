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

func TestHash128(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		seed       uint32
		expectedH1 uint64
		expectedH2 uint64
	}{
		{
			name:       "empty input with seed 0",
			data:       []byte{},
			seed:       0,
			expectedH1: 0,
			expectedH2: 0,
		},
		{
			name:       "empty input with seed 42",
			data:       []byte{},
			seed:       42,
			expectedH1: 17305828677633410339,
			expectedH2: 15060430851467758521,
		},
		{
			name:       "single byte",
			data:       []byte{0x42},
			seed:       0,
			expectedH1: 13609119272785792230,
			expectedH2: 16499902383673028068,
		},
		{
			name:       "hello world with seed 0",
			data:       []byte("hello world"),
			seed:       0,
			expectedH1: 5998619086395760910,
			expectedH2: 12364428806279881649,
		},
		{
			name:       "hello world with seed 123",
			data:       []byte("hello world"),
			seed:       123,
			expectedH1: 3184134337056710880,
			expectedH2: 6735459307601781589,
		},
		{
			name:       "exactly 16 bytes",
			data:       []byte("0123456789abcdef"),
			seed:       0,
			expectedH1: 5467490433528156583,
			expectedH2: 9782763267945859290,
		},
		{
			name:       "more than 16 bytes",
			data:       []byte("0123456789abcdef0123456789"),
			seed:       0,
			expectedH1: 9554952042823857868,
			expectedH2: 7769558039678505135,
		},
		{
			name:       "32 bytes - exactly 2 blocks",
			data:       []byte("0123456789abcdef0123456789abcdef"),
			seed:       0,
			expectedH1: 5708918040068455610,
			expectedH2: 1203913688419142818,
		},
		{
			name:       "all tail cases - 15 bytes",
			data:       []byte("012345678901234"),
			seed:       0,
			expectedH1: 11867552070264469923,
			expectedH2: 3266839343213454983,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h1, h2 := Hash128(tt.data, tt.seed)
			if h1 != tt.expectedH1 || h2 != tt.expectedH2 {
				t.Errorf("Hash128(%q, %d) = (%d, %d), want (%d, %d)",
					tt.data, tt.seed, h1, h2, tt.expectedH1, tt.expectedH2)
			}
		})
	}
}

func TestHash128_Deterministic(t *testing.T) {
	testData := []byte("test data for deterministic check")
	seed := uint32(42)

	h1_1, h2_1 := Hash128(testData, seed)
	h1_2, h2_2 := Hash128(testData, seed)

	if h1_1 != h1_2 || h2_1 != h2_2 {
		t.Errorf("Hash128 is not deterministic: first call (%d, %d), second call (%d, %d)",
			h1_1, h2_1, h1_2, h2_2)
	}
}

func TestHash128_DifferentInputs(t *testing.T) {
	data1 := []byte("test data 1")
	data2 := []byte("test data 2")
	seed := uint32(0)

	h1_1, h2_1 := Hash128(data1, seed)
	h1_2, h2_2 := Hash128(data2, seed)

	if h1_1 == h1_2 && h2_1 == h2_2 {
		t.Errorf("Different inputs produced same hash: (%d, %d)", h1_1, h2_1)
	}
}

func TestHash128_AllTailLengths(t *testing.T) {
	// Test all tail lengths from 0 to 15 bytes
	seed := uint32(0)
	baseData := []byte("0123456789abcdef") // 16 bytes base

	for tailLen := 0; tailLen <= 15; tailLen++ {
		data := append(baseData, []byte("extra tail bytes")[:tailLen]...)
		h1, h2 := Hash128(data, seed)

		// Verify it doesn't panic and produces some output
		if h1 == 0 && h2 == 0 && len(data) > 0 {
			t.Errorf("Hash128 with tail length %d produced zero hash for non-empty input", tailLen)
		}
	}
}

func Test_rotl64(t *testing.T) {
	tests := []struct {
		name     string
		x        uint64
		r        int8
		expected uint64
	}{
		{
			name:     "rotate 0 positions",
			x:        0x0123456789abcdef,
			r:        0,
			expected: 0x0123456789abcdef,
		},
		{
			name:     "rotate 1 position",
			x:        0x0123456789abcdef,
			r:        1,
			expected: 0x02468acf13579bde,
		},
		{
			name:     "rotate 8 positions",
			x:        0x0123456789abcdef,
			r:        8,
			expected: 0x23456789abcdef01,
		},
		{
			name:     "rotate 32 positions",
			x:        0x0123456789abcdef,
			r:        32,
			expected: 0x89abcdef01234567,
		},
		{
			name:     "rotate 64 positions (full circle)",
			x:        0x0123456789abcdef,
			r:        64,
			expected: 0x0123456789abcdef,
		},
		{
			name:     "rotate all 1s",
			x:        0xffffffffffffffff,
			r:        13,
			expected: 0xffffffffffffffff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rotl64(tt.x, tt.r)
			if result != tt.expected {
				t.Errorf("rotl64(0x%x, %d) = 0x%x, want 0x%x",
					tt.x, tt.r, result, tt.expected)
			}
		})
	}
}

func Test_fmix64(t *testing.T) {
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
		{
			name:     "test value 1",
			input:    0x0123456789abcdef,
			expected: 0x87cbfbfe89022cea,
		},
		{
			name:     "test value 2",
			input:    0xfedcba9876543210,
			expected: 0x03ebebcc1f4a6fd7,
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

func Test_fmix64_Avalanche(t *testing.T) {
	// Test that changing a single bit in input changes many bits in output
	input1 := uint64(0x0123456789abcdef)
	input2 := uint64(0x0123456789abcdee) // flip last bit

	output1 := fmix64(input1)
	output2 := fmix64(input2)

	if output1 == output2 {
		t.Errorf("fmix64 failed avalanche test: same output for different inputs")
	}

	// Count changed bits
	xor := output1 ^ output2
	changedBits := 0
	for xor != 0 {
		changedBits++
		xor &= xor - 1
	}

	// Expect significant bit change (at least 20 out of 64 bits)
	if changedBits < 20 {
		t.Errorf("fmix64 avalanche effect too weak: only %d bits changed", changedBits)
	}
}

func BenchmarkHash128_Small(b *testing.B) {
	data := []byte("hello")
	seed := uint32(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash128(data, seed)
	}
}

func BenchmarkHash128_Medium(b *testing.B) {
	data := make([]byte, 128)
	for i := range data {
		data[i] = byte(i)
	}
	seed := uint32(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash128(data, seed)
	}
}

func BenchmarkHash128_Large(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	seed := uint32(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash128(data, seed)
	}
}

func TestHash128_UnalignedInput(t *testing.T) {
    // Create a buffer and then a sub-slice that is not 8-byte aligned.
    buf := make([]byte, 33)
    for i := range buf {
        buf[i] = byte(i)
    }
    unalignedData := buf[1:] // len=32

    defer func() {
        if r := recover(); r != nil {
            t.Errorf("Hash128 panicked on unaligned data: %v", r)
        }
    }()

    Hash128(unalignedData, 0)
}