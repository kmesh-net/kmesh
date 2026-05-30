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
	"strings"
	"testing"
)

func TestNamespaceOrDefault(t *testing.T) {
	tests := []struct {
		ns   string
		want string
	}{
		{"", "default"},
		{"foo", "foo"},
		{"default", "default"},
	}
	for _, tt := range tests {
		got := namespaceOrDefault(tt.ns)
		if got != tt.want {
			t.Errorf("namespaceOrDefault(%q) = %q, want %q", tt.ns, got, tt.want)
		}
	}
}

func TestGetKmeshWaypointImage(t *testing.T) {
	oldImage := image
	t.Cleanup(func() {
		image = oldImage
	})

	// Test when image variable is set manually
	image = "my-custom-image:latest"
	got := getKmeshWaypointImage()
	if got != "my-custom-image:latest" {
		t.Errorf("expected custom image %q, got %q", "my-custom-image:latest", got)
	}

	// Reset image to default and check if it generates one based on version
	image = ""
	got = getKmeshWaypointImage()
	if !strings.Contains(got, "ghcr.io/kmesh-net/waypoint:") {
		t.Errorf("expected default image format, got %q", got)
	}
}

func TestNewCmd(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "waypoint" {
		t.Errorf("expected command Use to be %q, got %q", "waypoint", cmd.Use)
	}

	// Verify subcommands exist
	expectedSubcmds := []string{"list", "delete", "status", "generate", "apply"}
	for _, sub := range expectedSubcmds {
		found := false
		for _, c := range cmd.Commands() {
			if c.Name() == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subcommand %q to be registered", sub)
		}
	}
}
