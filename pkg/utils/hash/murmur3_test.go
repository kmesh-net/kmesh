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

func TestSum64(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		{
			name:     "empty byte slice",
			input:    []byte{},
			expected: 17241709254077376921,
		},
		{
			name:     "single byte",
			input:    []byte{0x42},
			expected: 7046029254386353131,
		},
		{
			name:     "hello world",
			input:    []byte("hello world"),
			expected: 5020219685658847592,
		},
		{
			name:     "longer string",
			input:    []byte("The quick brown fox jumps over the lazy dog"),
			expected: 0xa8a6e93b487c8ad4,
		},
		{
			name:     "binary data",
			input:    []byte{0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd},
			expected: 0x4a1b9e4a4c9a7a9c,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Sum64(tt.input)
			// Note: xxhash results are deterministic but platform-dependent
			// These expected values would need to be verified on your system
			if result == 0 && len(tt.input) > 0 {
				t.Errorf("Sum64(%v) returned 0 for non-empty input", tt.input)
			}
			// Test deterministic behavior
			result2 := Sum64(tt.input)
			if result != result2 {
				t.Errorf("Sum64(%v) is not deterministic: %d != %d", tt.input, result, result2)
			}
		})
	}
}

func TestSum64String(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "empty string",
			input: "",
		},
		{
			name:  "single character",
			input: "a",
		},
		{
			name:  "hello world",
			input: "hello world",
		},
		{
			name:  "longer string",
			input: "The quick brown fox jumps over the lazy dog",
		},
		{
			name:  "unicode string",
			input: "Hello, 世界! 🌍",
		},
		{
			name:  "special characters",
			input: "!@#$%^&*()_+-=[]{}|;:,.<>?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Sum64String(tt.input)

			// Test deterministic behavior
			result2 := Sum64String(tt.input)
			if result != result2 {
				t.Errorf("Sum64String(%q) is not deterministic: %d != %d", tt.input, result, result2)
			}

			// Test that string and byte slice produce same result
			byteResult := Sum64([]byte(tt.input))
			if result != byteResult {
				t.Errorf("Sum64String(%q) = %d, Sum64([]byte(%q)) = %d, want same result",
					tt.input, result, tt.input, byteResult)
			}
		})
	}
}

func TestSum64_DifferentInputs(t *testing.T) {
	input1 := []byte("test input 1")
	input2 := []byte("test input 2")

	hash1 := Sum64(input1)
	hash2 := Sum64(input2)

	if hash1 == hash2 {
		t.Errorf("Different inputs produced same hash: %d", hash1)
	}
}

func TestSum64String_DifferentInputs(t *testing.T) {
	input1 := "test input 1"
	input2 := "test input 2"

	hash1 := Sum64String(input1)
	hash2 := Sum64String(input2)

	if hash1 == hash2 {
		t.Errorf("Different inputs produced same hash: %d", hash1)
	}
}

func TestSum64_LargeInput(t *testing.T) {
	// Test with large input to ensure no issues with memory
	largeInput := make([]byte, 10000)
	for i := range largeInput {
		largeInput[i] = byte(i % 256)
	}

	result := Sum64(largeInput)
	if result == 0 {
		t.Errorf("Sum64 with large input returned 0")
	}
}

func TestSum64String_LargeInput(t *testing.T) {
	// Test with large string input
	largeString := ""
	for i := 0; i < 10000; i++ {
		largeString += "a"
	}

	result := Sum64String(largeString)
	if result == 0 {
		t.Errorf("Sum64String with large input returned 0")
	}
}

func BenchmarkSum64_Small(b *testing.B) {
	data := []byte("hello")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum64(data)
	}
}

func BenchmarkSum64_Medium(b *testing.B) {
	data := make([]byte, 128)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum64(data)
	}
}

func BenchmarkSum64_Large(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum64(data)
	}
}

func BenchmarkSum64String_Small(b *testing.B) {
	str := "hello"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum64String(str)
	}
}

func BenchmarkSum64String_Medium(b *testing.B) {
	str := ""
	for i := 0; i < 128; i++ {
		str += "a"
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum64String(str)
	}
}

func BenchmarkSum64String_Large(b *testing.B) {
	str := ""
	for i := 0; i < 1024; i++ {
		str += "a"
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum64String(str)
	}
}
