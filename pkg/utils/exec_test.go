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

package utils

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecute(t *testing.T) {
	tests := []struct {
		name    string
		script  string
		wantErr bool
		errHas  []string
	}{
		{
			name:    "exit 0 without output",
			script:  "exit 0",
			wantErr: false,
		},
		{
			name: "exit 0 with stderr warning is not a failure",
			// iptables prints "# Warning: iptables-legacy tables present" on stderr
			// and still exits 0 on hosts with the nft wrapper.
			script:  "echo '# Warning: iptables-legacy tables present' >&2; exit 0",
			wantErr: false,
		},
		{
			name:    "non-zero exit without stderr is a failure",
			script:  "exit 3",
			wantErr: true,
			errHas:  []string{"exit status 3"},
		},
		{
			name:    "non-zero exit keeps both the exit status and the stderr text",
			script:  "echo 'no such rule' >&2; exit 1",
			wantErr: true,
			errHas:  []string{"exit status 1", "no such rule"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Execute("sh", []string{"-c", tt.script})
			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}
			assert.Error(t, err)
			for _, s := range tt.errHas {
				assert.Contains(t, err.Error(), s)
			}
		})
	}
}

func TestExecuteMissingCommand(t *testing.T) {
	err := Execute("kmesh-no-such-command-for-test", nil)
	assert.Error(t, err)
}

func TestExecuteWithRedirect(t *testing.T) {
	t.Run("nil stdout is rejected", func(t *testing.T) {
		err := ExecuteWithRedirect("sh", []string{"-c", "exit 0"}, nil)
		assert.Error(t, err)
	})

	t.Run("stdout is redirected and stderr warning is not a failure", func(t *testing.T) {
		stdout := &bytes.Buffer{}
		err := ExecuteWithRedirect("sh", []string{"-c", "echo out; echo warn >&2; exit 0"}, stdout)
		assert.NoError(t, err)
		assert.Equal(t, "out\n", stdout.String())
	})

	t.Run("non-zero exit is a failure", func(t *testing.T) {
		stdout := &bytes.Buffer{}
		err := ExecuteWithRedirect("sh", []string{"-c", "echo bad >&2; exit 2"}, stdout)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exit status 2")
		assert.Contains(t, err.Error(), "bad")
	})
}
