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

package waypoint

import (
	"testing"
)

func TestNewCmd(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "waypoint" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "waypoint")
	}

	got := map[string]bool{}
	for _, sub := range cmd.Commands() {
		got[sub.Name()] = true
	}
	for _, want := range []string{"apply", "generate", "list", "delete", "status"} {
		if !got[want] {
			t.Errorf("subcommand %q not registered", want)
		}
	}
}

func TestNamespaceOrDefault(t *testing.T) {
	tests := []struct {
		ns   string
		want string
	}{
		{"", "default"},
		{"foo", "foo"},
	}
	for _, tt := range tests {
		if got := namespaceOrDefault(tt.ns); got != tt.want {
			t.Errorf("namespaceOrDefault(%q) = %q, want %q", tt.ns, got, tt.want)
		}
	}
}
