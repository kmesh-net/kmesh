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

package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBpfConfigParseConfigMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{name: "kernel-native is valid", mode: "kernel-native", wantErr: false},
		{name: "dual-engine is valid", mode: "dual-engine", wantErr: false},
		{name: "missing hyphen is invalid", mode: "dualengine", wantErr: true},
		{name: "underscore is invalid", mode: "kernel_native", wantErr: true},
		{name: "empty mode is invalid", mode: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &BpfConfig{
				Mode:        tt.mode,
				Cgroup2Path: t.TempDir(),
				BpfFsPath:   t.TempDir(),
			}
			err := c.ParseConfig()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
