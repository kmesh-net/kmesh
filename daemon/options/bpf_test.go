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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestBpfVerifierLogLevelFlag(t *testing.T) {
	cfg := &BpfConfig{}
	cmd := &cobra.Command{Use: "kmesh-daemon"}
	cfg.AttachFlags(cmd)

	// Disabled by default, matching existing behavior when the flag is unset.
	assert.Equal(t, uint32(0), cfg.BpfVerifierLogLevel)

	assert.NoError(t, cmd.ParseFlags([]string{"--bpf-verifier-log-level=3"}))
	assert.Equal(t, uint32(3), cfg.BpfVerifierLogLevel)
}
