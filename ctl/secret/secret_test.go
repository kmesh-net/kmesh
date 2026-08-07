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

package secret

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestNewCmd(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "secret" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "secret")
	}

	wantSubcommands := map[string]bool{"create": false, "get": false, "delete": false}
	for _, sub := range cmd.Commands() {
		name := sub.Name()
		if _, ok := wantSubcommands[name]; ok {
			wantSubcommands[name] = true
		}
		if sub.RunE == nil {
			t.Errorf("subcommand %q: RunE must be set so errors propagate instead of being silently swallowed", name)
		}
		if name == "create" && sub.Flags().Lookup("key") == nil {
			t.Error("create subcommand: --key flag not defined")
		}
	}
	for name, found := range wantSubcommands {
		if !found {
			t.Errorf("expected subcommand %q not found", name)
		}
	}
}

func keyCmd(t *testing.T, key string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().StringP("key", "k", "", "key of the encryption")
	if key != "" {
		if err := cmd.Flags().Set("key", key); err != nil {
			t.Fatalf("failed to set --key: %v", err)
		}
	}
	return cmd
}

func TestCreateOrUpdateSecret_InvalidHex(t *testing.T) {
	cmd := keyCmd(t, "not-valid-hex!!")
	if err := CreateOrUpdateSecret(cmd, nil); err == nil {
		t.Fatal("CreateOrUpdateSecret(invalid hex key) = nil error, want a validation error")
	}
}

func TestCreateOrUpdateSecret_InvalidKeyLength(t *testing.T) {
	cmd := keyCmd(t, "ab") // valid hex, far short of AeadKeyLength bytes
	if err := CreateOrUpdateSecret(cmd, nil); err == nil {
		t.Fatal("CreateOrUpdateSecret(wrong-length key) = nil error, want a validation error")
	}
}
