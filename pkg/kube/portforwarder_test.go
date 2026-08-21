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

package kube

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPortForwarder(t *testing.T) {
	tests := []struct {
		name             string
		ns               string
		localAddress     string
		localPort        int
		podPort          int
		wantAddress      []string
		wantNamespace    string
		wantLocalAddress string
	}{
		{
			name:             "custom namespace and address",
			ns:               "my-ns",
			localAddress:     "0.0.0.0",
			localPort:        8080,
			podPort:          15008,
			wantAddress:      []string{"0.0.0.0"},
			wantNamespace:    "my-ns",
			wantLocalAddress: "0.0.0.0",
		},
		{
			name:             "empty address falls back to localhost",
			ns:               "my-ns",
			localAddress:     "",
			localPort:        0,
			podPort:          15001,
			wantAddress:      []string{DefaultLocalAddress},
			wantNamespace:    "my-ns",
			wantLocalAddress: DefaultLocalAddress,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw, err := newPortForwarder(&client{}, "test-pod", tt.ns, tt.localAddress, tt.localPort, tt.podPort)
			require.NoError(t, err)

			pf, ok := fw.(*portForwarder)
			require.True(t, ok)

			address, err := pf.cmd.Flags().GetStringSlice("address")
			require.NoError(t, err)
			assert.Equal(t, tt.wantAddress, address)

			namespace, err := pf.cmd.Flags().GetString("namespace")
			require.NoError(t, err)
			assert.Equal(t, tt.wantNamespace, namespace)

			assert.Equal(t, tt.ns, pf.ns)
			assert.Equal(t, tt.podPort, pf.podPort)
			assert.Equal(t, tt.wantLocalAddress, pf.localAddress)

			if tt.localPort == 0 {
				assert.NotZero(t, pf.localPort)
			} else {
				assert.Equal(t, tt.localPort, pf.localPort)
			}
		})
	}
}
