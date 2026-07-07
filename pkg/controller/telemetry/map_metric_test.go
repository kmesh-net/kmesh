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

package telemetry

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
)

func TestBuildMapMetricLabel(t *testing.T) {
	os.Setenv("NODE_NAME", "test-node")
	defer os.Unsetenv("NODE_NAME")
	tests := []struct {
		name     string
		data     *MapInfo
		expected mapMetricLabels
	}{
		{
			name: "valid MapInfo",
			data: &MapInfo{mapName: "kmesh_map", entryCount: 5},
			expected: mapMetricLabels{
				mapName:  "kmesh_map",
				nodeName: "test-node",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildMapMetricLabel(tt.data)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestBuildMapDetailMetricLabel(t *testing.T) {
	os.Setenv("NODE_NAME", "test-node")
	defer os.Unsetenv("NODE_NAME")

	data := &MapInfo{
		mapName: "kmesh_map",
		mapType: "Hash",
	}

	got := buildMapDetailMetricLabel(data)
	assert.Equal(t, mapDetailMetricLabels{
		mapName:  "kmesh_map",
		mapType:  "Hash",
		nodeName: "test-node",
	}, got)
}

func TestCalculateMapEntryUtilization(t *testing.T) {
	tests := []struct {
		name       string
		entryCount uint32
		maxEntries uint32
		expected   float64
	}{
		{
			name:       "normal ratio",
			entryCount: 50,
			maxEntries: 200,
			expected:   0.25,
		},
		{
			name:       "zero max entries",
			entryCount: 50,
			maxEntries: 0,
			expected:   0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateMapEntryUtilization(tt.entryCount, tt.maxEntries)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestBuildMapMetricData(t *testing.T) {
	tests := []struct {
		name         string
		info         *ebpf.MapInfo
		entryCount   uint32
		hasEntry     bool
		memlockBytes uint64
		hasMemlock   bool
		expected     MapInfo
	}{
		{
			name: "memlock available",
			info: &ebpf.MapInfo{
				Name:       "kmesh_frontend",
				Type:       ebpf.Hash,
				MaxEntries: 1024,
			},
			entryCount:   100,
			hasEntry:     true,
			memlockBytes: 2048,
			hasMemlock:   true,
			expected: MapInfo{
				mapName:     "kmesh_frontend",
				mapType:     ebpf.Hash.String(),
				entryCount:  100,
				hasEntry:    true,
				maxEntries:  1024,
				memlockByte: 2048,
				hasMemlock:  true,
			},
		},
		{
			name: "memlock missing",
			info: &ebpf.MapInfo{
				Name:       "kmesh_backend",
				Type:       ebpf.Array,
				MaxEntries: 512,
			},
			entryCount:   12,
			hasEntry:     false,
			memlockBytes: 0,
			hasMemlock:   false,
			expected: MapInfo{
				mapName:     "kmesh_backend",
				mapType:     ebpf.Array.String(),
				entryCount:  12,
				hasEntry:    false,
				maxEntries:  512,
				memlockByte: 0,
				hasMemlock:  false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildMapMetricData(tt.info, tt.entryCount, tt.hasEntry, tt.memlockBytes, tt.hasMemlock)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestIsKmeshMap(t *testing.T) {
	tests := []struct {
		name     string
		mapName  string
		expected bool
	}{
		{name: "valid kmesh map", mapName: "kmesh_test_map", expected: true},
		{name: "invalid map name", mapName: "other_map", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isKmeshMap(tt.mapName))
		})
	}
}
