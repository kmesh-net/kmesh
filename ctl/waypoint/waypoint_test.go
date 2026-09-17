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
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"istio.io/istio/pkg/config/constants"
	gateway "sigs.k8s.io/gateway-api/apis/v1"

	"kmesh.net/kmesh/pkg/version"
)

func resetWaypointGlobals() {
	revision = ""
	waitReady = false
	allNamespaces = false
	namespace = ""
	deleteAll = false
	trafficType = ""
	image = ""
	waypointName = constants.DefaultNamespaceWaypoint
	enrollNamespace = false
	overwrite = false
}

func TestNamespaceOrDefault(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		want      string
	}{
		{name: "empty uses default", namespace: "", want: "default"},
		{name: "explicit namespace", namespace: "foo", want: "foo"},
		{name: "kube-system", namespace: "kube-system", want: "kube-system"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := namespaceOrDefault(tt.namespace); got != tt.want {
				t.Errorf("namespaceOrDefault(%q) = %q, want %q", tt.namespace, got, tt.want)
			}
		})
	}
}

func TestGetKmeshWaypointImage(t *testing.T) {
	t.Cleanup(resetWaypointGlobals)

	t.Run("custom image", func(t *testing.T) {
		image = "example.com/custom-waypoint:v1"
		defer resetWaypointGlobals()
		if got := getKmeshWaypointImage(); got != image {
			t.Errorf("getKmeshWaypointImage() = %q, want %q", got, image)
		}
	})

	t.Run("default from version", func(t *testing.T) {
		image = ""
		defer resetWaypointGlobals()
		ver := strings.TrimPrefix(version.Get().GitVersion, "v")
		want := fmt.Sprintf("ghcr.io/kmesh-net/waypoint:v%s", ver)
		if got := getKmeshWaypointImage(); got != want {
			t.Errorf("getKmeshWaypointImage() = %q, want %q", got, want)
		}
	})
}

func TestErrorWithMessage(t *testing.T) {
	gwc := &gateway.Gateway{}
	gwc.Namespace = "default"
	gwc.Name = "waypoint"

	t.Run("without nested error", func(t *testing.T) {
		err := errorWithMessage("timed out", gwc, nil)
		want := "timed out\tdefault/waypoint"
		if err == nil || err.Error() != want {
			t.Errorf("errorWithMessage() = %v, want %q", err, want)
		}
	})

	t.Run("with nested error", func(t *testing.T) {
		err := errorWithMessage("timed out", gwc, errors.New("boom"))
		want := "timed out\tdefault/waypoint: boom"
		if err == nil || err.Error() != want {
			t.Errorf("errorWithMessage() = %v, want %q", err, want)
		}
	})
}

func TestNewCmd(t *testing.T) {
	t.Cleanup(resetWaypointGlobals)

	cmd := NewCmd()
	if cmd.Use != "waypoint" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "waypoint")
	}

	for _, name := range []string{"generate", "apply", "delete", "list", "status"} {
		if findSubcommand(cmd, name) == nil {
			t.Errorf("missing subcommand %q", name)
		}
	}

	for _, name := range []string{"namespace", "name", "image"} {
		if cmd.PersistentFlags().Lookup(name) == nil {
			t.Errorf("persistent flag --%s not defined", name)
		}
	}

	generate := findSubcommand(cmd, "generate")
	if generate.Flags().Lookup("for") == nil {
		t.Error("generate --for flag not defined")
	}
	if generate.Flags().Lookup("revision") == nil {
		t.Error("generate --revision flag not defined")
	}

	apply := findSubcommand(cmd, "apply")
	for _, name := range []string{"for", "enroll-namespace", "overwrite", "revision", "wait"} {
		if apply.Flags().Lookup(name) == nil {
			t.Errorf("apply --%s flag not defined", name)
		}
	}

	if findSubcommand(cmd, "delete").Flags().Lookup("all") == nil {
		t.Error("delete --all flag not defined")
	}
	if findSubcommand(cmd, "list").Flags().Lookup("all-namespaces") == nil {
		t.Error("list --all-namespaces flag not defined")
	}
}

func TestGenerateValidation(t *testing.T) {
	t.Cleanup(resetWaypointGlobals)

	t.Run("rejects reserved name none", func(t *testing.T) {
		defer resetWaypointGlobals()
		cmd := NewCmd()
		buf := &bytes.Buffer{}
		cmd.SetOut(buf)
		cmd.SetErr(buf)
		cmd.SetArgs([]string{"generate", "--name", "none"})
		err := cmd.Execute()
		if err == nil {
			t.Fatal("expected error for name 'none'")
		}
		if !strings.Contains(err.Error(), "none") {
			t.Errorf("error = %v, want mention of reserved name", err)
		}
	})

	t.Run("rejects invalid traffic type", func(t *testing.T) {
		defer resetWaypointGlobals()
		cmd := NewCmd()
		buf := &bytes.Buffer{}
		cmd.SetOut(buf)
		cmd.SetErr(buf)
		cmd.SetArgs([]string{"generate", "--for", "invalid"})
		err := cmd.Execute()
		if err == nil {
			t.Fatal("expected error for invalid traffic type")
		}
		if !strings.Contains(err.Error(), "invalid traffic type") {
			t.Errorf("error = %v, want invalid traffic type", err)
		}
	})

	t.Run("emits gateway yaml", func(t *testing.T) {
		defer resetWaypointGlobals()
		cmd := NewCmd()
		buf := &bytes.Buffer{}
		cmd.SetOut(buf)
		cmd.SetErr(buf)
		cmd.SetArgs([]string{"generate", "--namespace", "default", "--name", "my-waypoint", "--for", "service"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("generate failed: %v", err)
		}
		out := buf.String()
		for _, want := range []string{
			"kind: Gateway",
			"name: my-waypoint",
			"namespace: default",
			constants.WaypointGatewayClassName,
			KmeshWaypointForTrafficTypeLabel + ": service",
			WaypointImageAnnotation,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("generate output missing %q\n%s", want, out)
			}
		}
	})
}

func findSubcommand(cmd *cobra.Command, name string) *cobra.Command {
	for _, sub := range cmd.Commands() {
		if sub.Name() == name {
			return sub
		}
	}
	return nil
}
