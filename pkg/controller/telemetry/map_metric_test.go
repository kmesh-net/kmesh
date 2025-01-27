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
