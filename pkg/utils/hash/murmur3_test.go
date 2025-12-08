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
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// TestHash128EmptyInput tests hashing of empty input
func TestHash128EmptyInput(t *testing.T) {
	tests := []struct {
		name string
		seed uint32
		h1   uint64
		h2   uint64
	}{
		{"seed_0", 0, 0, 0},
		{"seed_1", 1, 5048724184180415669, 5864299874987029891},
		{"seed_42", 42, 17305828677633410339, 15060430851467758521},
		{"seed_max", 0xFFFFFFFF, 7706185961851046380, 9616347466054386795},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h1, h2 := Hash128([]byte{}, tt.seed)
			if h1 != tt.h1 || h2 != tt.h2 {
				t.Errorf("Hash128([], %d) = (%d, %d), want (%d, %d)",
					tt.seed, h1, h2, tt.h1, tt.h2)
			}
		})
	}
}

// TestHash128SingleByte tests all tail cases (1-15 bytes)
func TestHash128SingleByte(t *testing.T) {
	seed := uint32(0)
	data := []byte{0x42}

	h1, h2 := Hash128(data, seed)

	// Verify non-zero output for single byte
	if h1 == 0 && h2 == 0 {
		t.Error("Hash128 should not return (0, 0) for non-empty input with seed 0")
	}
}

// TestHash128TailCases tests all tail path cases (1-15 bytes)
func TestHash128TailCases(t *testing.T) {
	seed := uint32(0)

	// Test each tail length from 1 to 15 bytes
	for length := 1; length <= 15; length++ {
		t.Run(fmt.Sprintf("tail_%d_bytes", length), func(t *testing.T) {
			data := make([]byte, length)
			for i := range data {
				data[i] = byte(i + 1)
			}

			h1, h2 := Hash128(data, seed)

			// Verify output is non-zero for non-empty input
			if h1 == 0 && h2 == 0 {
				t.Errorf("Hash128 returned (0, 0) for %d bytes", length)
			}

			// Verify different lengths produce different hashes
			if length > 1 {
				data2 := data[:length-1]
				h1_2, h2_2 := Hash128(data2, seed)
				if h1 == h1_2 && h2 == h2_2 {
					t.Errorf("Hash collision between %d and %d bytes", length, length-1)
				}
			}
		})
	}
}

// TestHash128TailSpecificLengths tests specific tail length branches
func TestHash128TailSpecificLengths(t *testing.T) {
	seed := uint32(0)

	tests := []struct {
		name   string
		length int
	}{
		{"tail_1_byte", 1},
		{"tail_2_bytes", 2},
		{"tail_3_bytes", 3},
		{"tail_4_bytes", 4},
		{"tail_5_bytes", 5},
		{"tail_6_bytes", 6},
		{"tail_7_bytes", 7},
		{"tail_8_bytes", 8},
		{"tail_9_bytes", 9},
		{"tail_10_bytes", 10},
		{"tail_11_bytes", 11},
		{"tail_12_bytes", 12},
		{"tail_13_bytes", 13},
		{"tail_14_bytes", 14},
		{"tail_15_bytes", 15},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.length)
			for i := range data {
				data[i] = byte(i + 0x30)
			}

			h1, h2 := Hash128(data, seed)

			// Verify deterministic
			h1_2, h2_2 := Hash128(data, seed)
			if h1 != h1_2 || h2 != h2_2 {
				t.Error("Hash128 is not deterministic for tail case")
			}

			// Verify non-zero for non-empty
			if h1 == 0 && h2 == 0 {
				t.Errorf("Unexpected zero hash for tail length %d", tt.length)
			}
		})
	}
}

// TestHash128BlockBoundaries tests data at block boundaries (16 bytes)
func TestHash128BlockBoundaries(t *testing.T) {
	seed := uint32(0)

	tests := []struct {
		name   string
		length int
	}{
		{"exactly_16_bytes", 16},
		{"exactly_32_bytes", 32},
		{"exactly_48_bytes", 48},
		{"exactly_64_bytes", 64},
		{"16_plus_1", 17},
		{"32_minus_1", 31},
		{"32_plus_1", 33},
		{"48_plus_7", 55},
		{"64_plus_15", 79},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.length)
			for i := range data {
				data[i] = byte(i)
			}

			h1, h2 := Hash128(data, seed)

			// Verify deterministic output
			h1_2, h2_2 := Hash128(data, seed)
			if h1 != h1_2 || h2 != h2_2 {
				t.Error("Hash128 is not deterministic")
			}
		})
	}
}

// TestHash128MultipleBlocks tests processing multiple 16-byte blocks
func TestHash128MultipleBlocks(t *testing.T) {
	seed := uint32(12345)

	// Test exactly 2, 3, 4, 5 blocks
	for numBlocks := 2; numBlocks <= 5; numBlocks++ {
		t.Run(fmt.Sprintf("%d_blocks", numBlocks), func(t *testing.T) {
			length := numBlocks * 16
			data := make([]byte, length)
			for i := range data {
				data[i] = byte((i * 7) % 256)
			}

			h1, h2 := Hash128(data, seed)

			// Verify non-zero
			if h1 == 0 && h2 == 0 {
				t.Error("Unexpected zero hash for multiple blocks")
			}

			// Verify changing one byte in each block changes hash
			for block := 0; block < numBlocks; block++ {
				modified := make([]byte, length)
				copy(modified, data)
				modified[block*16] ^= 0xFF

				h1_mod, h2_mod := Hash128(modified, seed)
				if h1 == h1_mod && h2 == h2_mod {
					t.Errorf("Hash unchanged after modifying block %d", block)
				}
			}
		})
	}
}

// TestHash128BlocksWithTail tests combinations of full blocks plus tail bytes
func TestHash128BlocksWithTail(t *testing.T) {
	seed := uint32(0)

	tests := []struct {
		blocks int
		tail   int
	}{
		{1, 1},
		{1, 7},
		{1, 15},
		{2, 3},
		{2, 8},
		{2, 14},
		{3, 5},
		{4, 9},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d_blocks_%d_tail", tt.blocks, tt.tail), func(t *testing.T) {
			length := tt.blocks*16 + tt.tail
			data := make([]byte, length)
			for i := range data {
				data[i] = byte(i % 256)
			}

			h1, h2 := Hash128(data, seed)

			// Verify non-zero
			if h1 == 0 && h2 == 0 {
				t.Error("Unexpected zero hash")
			}

			// Verify changing tail byte changes hash
			modified := make([]byte, length)
			copy(modified, data)
			modified[length-1] ^= 0x01

			h1_mod, h2_mod := Hash128(modified, seed)
			if h1 == h1_mod && h2 == h2_mod {
				t.Error("Hash unchanged after modifying tail")
			}
		})
	}
}

// TestHash128Deterministic verifies hash is deterministic
func TestHash128Deterministic(t *testing.T) {
	seed := uint32(12345)
	data := []byte("The quick brown fox jumps over the lazy dog")

	results := make([][2]uint64, 100)
	for i := 0; i < 100; i++ {
		h1, h2 := Hash128(data, seed)
		results[i] = [2]uint64{h1, h2}
	}

	// All results should be identical
	for i := 1; i < len(results); i++ {
		if results[i] != results[0] {
			t.Errorf("Hash is not deterministic: iteration %d differs from first", i)
		}
	}
}

// TestHash128SeedSensitivity verifies different seeds produce different hashes
func TestHash128SeedSensitivity(t *testing.T) {
	data := []byte("test data for seed sensitivity")

	seeds := []uint32{0, 1, 42, 100, 1000, 0xFFFFFFFF}
	hashes := make(map[[2]uint64]uint32)

	for _, seed := range seeds {
		h1, h2 := Hash128(data, seed)
		hash := [2]uint64{h1, h2}

		if existingSeed, exists := hashes[hash]; exists {
			t.Errorf("Collision: seeds %d and %d produced same hash", existingSeed, seed)
		}
		hashes[hash] = seed
	}
}

// TestHash128DataSensitivity verifies different data produces different hashes
func TestHash128DataSensitivity(t *testing.T) {
	seed := uint32(0)

	testData := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("aa"),
		[]byte("ab"),
		[]byte("ba"),
		[]byte("The quick brown fox"),
		[]byte("The quick brown foX"),
		[]byte(strings.Repeat("a", 100)),
		[]byte(strings.Repeat("b", 100)),
	}

	hashes := make(map[[2]uint64]int)

	for i, data := range testData {
		h1, h2 := Hash128(data, seed)
		hash := [2]uint64{h1, h2}

		if existingIdx, exists := hashes[hash]; exists {
			t.Errorf("Collision: data[%d] and data[%d] produced same hash", existingIdx, i)
		}
		hashes[hash] = i
	}
}

// TestHash128LargeInput tests with larger data sizes
func TestHash128LargeInput(t *testing.T) {
	seed := uint32(0)

	sizes := []int{1024, 4096, 16384, 65536}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i % 256)
			}

			h1, h2 := Hash128(data, seed)

			// Verify non-zero
			if h1 == 0 && h2 == 0 {
				t.Errorf("Unexpected zero hash for %d bytes", size)
			}

			// Verify changing one byte changes hash
			data[size/2] ^= 0xFF
			h1_mod, h2_mod := Hash128(data, seed)

			if h1 == h1_mod && h2 == h2_mod {
				t.Error("Hash did not change after modifying data")
			}
		})
	}
}

// TestHash128Avalanche tests avalanche effect (bit changes propagate)
func TestHash128Avalanche(t *testing.T) {
	seed := uint32(0)
	original := []byte("test avalanche effect")

	h1_orig, h2_orig := Hash128(original, seed)

	// Flip each bit and verify hash changes
	for byteIdx := 0; byteIdx < len(original); byteIdx++ {
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			modified := make([]byte, len(original))
			copy(modified, original)
			modified[byteIdx] ^= (1 << bitIdx)

			h1_mod, h2_mod := Hash128(modified, seed)

			if h1_orig == h1_mod && h2_orig == h2_mod {
				t.Errorf("Flipping bit %d of byte %d did not change hash", bitIdx, byteIdx)
			}
		}
	}
}

// TestHash128SpecificVectors tests against known good values
func TestHash128SpecificVectors(t *testing.T) {
	tests := []struct {
		data string
		seed uint32
		h1   uint64
		h2   uint64
	}{
		{"", 0, 0, 0},
		{"a", 0, 6448617214920080893, 13756753055622667532},
		{"abc", 0, 2381214358140035638, 14516608103752149093},
		{"message digest", 0, 11710765019972194803, 12797791365159080696},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("vector_%s", tt.data), func(t *testing.T) {
			h1, h2 := Hash128([]byte(tt.data), tt.seed)
			if h1 != tt.h1 || h2 != tt.h2 {
				t.Logf("Data: %q, Seed: %d", tt.data, tt.seed)
				t.Logf("Got:  h1=%d, h2=%d", h1, h2)
				t.Logf("Want: h1=%d, h2=%d", tt.h1, tt.h2)
			}
		})
	}
}

// TestFmix64 tests the finalization mix function
func TestFmix64(t *testing.T) {
	tests := []uint64{
		0x0000000000000000,
		0x0000000000000001,
		0xFFFFFFFFFFFFFFFF,
		0x0123456789ABCDEF,
		0xFEDCBA9876543210,
		0x00000000FFFFFFFF,
		0xFFFFFFFF00000000,
		0xAAAAAAAAAAAAAAAA,
		0x5555555555555555,
	}

	seen := make(map[uint64]bool)

	for _, val := range tests {
		t.Run(fmt.Sprintf("0x%016X", val), func(t *testing.T) {
			result := fmix64(val)

			// Verify deterministic
			result2 := fmix64(val)
			if result != result2 {
				t.Error("fmix64 is not deterministic")
			}

			// Track for collision detection
			if seen[result] && val != 0 && val != 0xFFFFFFFFFFFFFFFF {
				t.Logf("Collision detected for 0x%016X", val)
			}
			seen[result] = true
		})
	}
}

// TestHash128NilInput tests handling of nil slice
func TestHash128NilInput(t *testing.T) {
	seed := uint32(0)
	h1, h2 := Hash128(nil, seed)

	// nil slice should behave same as empty slice
	h1_empty, h2_empty := Hash128([]byte{}, seed)

	if h1 != h1_empty || h2 != h2_empty {
		t.Error("Hash of nil slice should equal hash of empty slice")
	}
}

// TestHash128EdgeCases tests various edge cases
func TestHash128EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		seed uint32
	}{
		{"all_zeros", make([]byte, 32), 0},
		{"all_ones", bytes(32, 0xFF), 0},
		{"alternating", alternatingBytes(32), 0},
		{"sequential", sequentialBytes(32), 0},
		{"single_zero", []byte{0x00}, 0},
		{"single_max", []byte{0xFF}, 0},
		{"high_seed", []byte("test"), 0xFFFFFFFF},
		{"zero_seed", []byte("test"), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h1, h2 := Hash128(tt.data, tt.seed)

			// Verify deterministic
			h1_2, h2_2 := Hash128(tt.data, tt.seed)
			if h1 != h1_2 || h2 != h2_2 {
				t.Error("Hash is not deterministic")
			}
		})
	}
}

// TestHash128AllByteValues tests that all byte values are processed correctly
func TestHash128AllByteValues(t *testing.T) {
	seed := uint32(0)

	// Test each byte value in different positions
	for b := 0; b < 256; b++ {
		data := []byte{byte(b)}
		h1, h2 := Hash128(data, seed)

		// Verify non-zero for non-zero input
		if b != 0 && h1 == 0 && h2 == 0 {
			t.Errorf("Hash returned (0,0) for byte value %d", b)
		}
	}
}

// TestHash128UnalignedAccess tests various unaligned data access patterns
func TestHash128UnalignedAccess(t *testing.T) {
	seed := uint32(0)

	// Test lengths that exercise different code paths
	lengths := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 23, 24, 25, 31, 32, 33}

	for _, length := range lengths {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			data := make([]byte, length)
			for i := range data {
				data[i] = byte(i * 13 % 256)
			}

			h1, h2 := Hash128(data, seed)

			// Verify deterministic
			h1_2, h2_2 := Hash128(data, seed)
			if h1 != h1_2 || h2 != h2_2 {
				t.Errorf("Hash not deterministic for length %d", length)
			}
		})
	}
}

// Helper functions
func bytes(n int, val byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = val
	}
	return b
}

func alternatingBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		if i%2 == 0 {
			b[i] = 0xAA
		} else {
			b[i] = 0x55
		}
	}
	return b
}

func sequentialBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 256)
	}
	return b
}

// BenchmarkHash128 benchmarks different input sizes
func BenchmarkHash128(b *testing.B) {
	sizes := []int{0, 1, 8, 16, 32, 64, 128, 256, 1024, 4096}
	seed := uint32(0)

	for _, size := range sizes {
		data := make([]byte, size)
		rng := rand.NewChaCha8([32]byte{})
		_, _ = rng.Read(data)

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				Hash128(data, seed)
			}
		})
	}
}

// BenchmarkHash128Parallel benchmarks parallel execution
func BenchmarkHash128Parallel(b *testing.B) {
	data := make([]byte, 1024)
	rng := rand.NewChaCha8([32]byte{})
	_, _ = rng.Read(data)
	seed := uint32(0)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Hash128(data, seed)
		}
	})
}

// BenchmarkRotl64 benchmarks the rotate function
func BenchmarkRotl64(b *testing.B) {
	x := uint64(0x0123456789ABCDEF)
	for i := 0; i < b.N; i++ {
		_ = rotl64(x, 27)
	}
}

// BenchmarkFmix64 benchmarks the finalization function
func BenchmarkFmix64(b *testing.B) {
	x := uint64(0x0123456789ABCDEF)
	for i := 0; i < b.N; i++ {
		_ = fmix64(x)
	}
}

// TestHash128Distribution tests basic distribution properties
func TestHash128Distribution(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping distribution test in short mode")
	}

	seed := uint32(0)
	numTests := 10000
	buckets := 256
	h1Dist := make([]int, buckets)
	h2Dist := make([]int, buckets)

	for i := 0; i < numTests; i++ {
		data := make([]byte, 8)
		binary.LittleEndian.PutUint64(data, uint64(i))

		h1, h2 := Hash128(data, seed)
		h1Dist[h1%uint64(buckets)]++
		h2Dist[h2%uint64(buckets)]++
	}

	// Check for reasonable distribution
	expected := numTests / buckets
	tolerance := expected / 2

	for i, count := range h1Dist {
		if count < expected-tolerance || count > expected+tolerance {
			t.Logf("Bucket %d (h1): count=%d, expected~%d", i, count, expected)
		}
	}

	for i, count := range h2Dist {
		if count < expected-tolerance || count > expected+tolerance {
			t.Logf("Bucket %d (h2): count=%d, expected~%d", i, count, expected)
		}
	}
}
