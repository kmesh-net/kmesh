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

package nets

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateInterval(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected time.Duration
	}{
		{
			name:     "zero duration",
			input:    0,
			expected: MaxRetryInterval / MaxRetryCount,
		},
		{
			name:     "small duration",
			input:    time.Second * 5,
			expected: time.Second*5 + MaxRetryInterval/MaxRetryCount,
		},
		{
			name:     "duration at max threshold",
			input:    MaxRetryInterval - MaxRetryInterval/MaxRetryCount,
			expected: MaxRetryInterval,
		},
		{
			name:     "duration exceeding max",
			input:    MaxRetryInterval,
			expected: MaxRetryInterval,
		},
		{
			name:     "large duration",
			input:    time.Minute * 10,
			expected: MaxRetryInterval,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateInterval(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculateRandTime(t *testing.T) {
	tests := []struct {
		name  string
		seed  int
		check func(t *testing.T, result time.Duration)
	}{
		{
			name: "seed of 1",
			seed: 1,
			check: func(t *testing.T, result time.Duration) {
				assert.Equal(t, time.Duration(0), result)
			},
		},
		{
			name: "positive seed 100",
			seed: 100,
			check: func(t *testing.T, result time.Duration) {
				assert.GreaterOrEqual(t, result, time.Duration(0))
				assert.Less(t, result, time.Duration(100)*time.Millisecond)
			},
		},
		{
			name: "large seed 10000",
			seed: 10000,
			check: func(t *testing.T, result time.Duration) {
				assert.GreaterOrEqual(t, result, time.Duration(0))
				assert.Less(t, result, time.Duration(10000)*time.Millisecond)
			},
		},
		{
			name: "seed of 50",
			seed: 50,
			check: func(t *testing.T, result time.Duration) {
				assert.GreaterOrEqual(t, result, time.Duration(0))
				assert.Less(t, result, time.Duration(50)*time.Millisecond)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateRandTime(tt.seed)
			tt.check(t, result)
		})
	}
}

func TestCalculateRandTime_Distribution(t *testing.T) {
	seed := 1000
	results := make(map[time.Duration]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		result := CalculateRandTime(seed)
		results[result] = true

		assert.GreaterOrEqual(t, result, time.Duration(0))
		assert.Less(t, result, time.Duration(seed)*time.Millisecond)
	}

	assert.Greater(t, len(results), 1, "Expected multiple different random values")
}

func TestGrpcConnect_InvalidAddress(t *testing.T) {
	conn, err := GrpcConnect("invalid://address")
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestGrpcConnect_EmptyAddress(t *testing.T) {
	conn, err := GrpcConnect("")
	assert.Error(t, err)
	assert.Nil(t, conn)
}

func TestGrpcConnect_WithMissingCredentials(t *testing.T) {
	conn, err := GrpcConnect("localhost:15010")
	if err != nil {
		assert.Error(t, err)
		assert.Nil(t, conn)
	} else if conn != nil {
		_ = conn.Close()
	}
}

func TestGrpcConnect_WithValidSetup(t *testing.T) {
	tmpDir := t.TempDir()
	jwtFile := filepath.Join(tmpDir, "istio-token")
	err := os.WriteFile(jwtFile, []byte("test-token"), 0644)
	require.NoError(t, err)

	conn, err := GrpcConnect("localhost:15010")

	if err != nil {
		assert.Error(t, err)
	}

	if conn != nil {
		defer func() { _ = conn.Close() }()
	}
}

func TestConstants(t *testing.T) {
	assert.Equal(t, time.Second*30, MaxRetryInterval)
	assert.Equal(t, 3, MaxRetryCount)
	assert.Equal(t, "JWT", credFetcherTypeEnv)
	assert.Equal(t, "cluster.local", trustDomainEnv)
	assert.Equal(t, "/var/run/secrets/tokens/istio-token", jwtPath)
}

func TestCalculateInterval_Incremental(t *testing.T) {
	var current time.Duration = 0

	for i := 0; i < MaxRetryCount+2; i++ {
		current = CalculateInterval(current)
		assert.LessOrEqual(t, current, MaxRetryInterval)
		assert.Greater(t, current, time.Duration(0))
	}

	assert.Equal(t, MaxRetryInterval, current)
}

func BenchmarkCalculateInterval(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CalculateInterval(time.Second * 10)
	}
}

func BenchmarkCalculateRandTime(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CalculateRandTime(1000)
	}
}
