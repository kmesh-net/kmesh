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

package dump

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestUint32ToIPStr(t *testing.T) {
	tests := []struct {
		ip   uint32
		want string
	}{
		{0x0100007F, "127.0.0.1"},
		{0x00000000, "0.0.0.0"},
		{0xFFFFFFFF, "255.255.255.255"},
		{0x0101A8C0, "192.168.1.1"},
		{0x0100000A, "10.0.0.1"},
	}
	for _, tt := range tests {
		if got := uint32ToIPStr(tt.ip); got != tt.want {
			t.Errorf("uint32ToIPStr(%#x) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer func() {
		os.Stdout = old
		_ = w.Close()
		_ = r.Close()
	}()

	os.Stdout = w
	fn()
	_ = w.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read captured stdout: %v", err)
	}
	return buf.String()
}

func TestPrintDualEngineTable(t *testing.T) {
	tests := []struct {
		name       string
		input      workloadDump
		wantEmpty  bool
		wantSubstr []string
	}{
		{
			name: "full dump",
			input: workloadDump{
				Workloads: []workloadEntry{
					{Name: "nginx", Namespace: "default", Addresses: []string{"10.0.0.1"}, Protocol: "TCP", Status: "Healthy"},
				},
				Services: []serviceEntry{
					{Name: "my-svc", Namespace: "default", Hostname: "my-svc.default.svc.cluster.local", Addresses: []string{"10.96.0.1"}},
				},
				Policies: []policyEntry{
					{Name: "allow-all", Namespace: "default", Scope: "namespace", Action: "ALLOW"},
				},
			},
			wantSubstr: []string{"nginx", "my-svc", "allow-all", "ALLOW", "TCP", "Healthy"},
		},
		{
			name:      "empty dump",
			input:     workloadDump{},
			wantEmpty: true,
		},
		{
			name: "workloads only with multiple addresses",
			input: workloadDump{
				Workloads: []workloadEntry{
					{Name: "app1", Namespace: "test", Addresses: []string{"10.0.0.2", "10.0.0.3"}, Protocol: "HTTP", Status: "Running"},
				},
			},
			wantSubstr: []string{"app1", "10.0.0.2,10.0.0.3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.input)
			out := captureStdout(t, func() { printDualEngineTable(body) })

			if tt.wantEmpty && strings.TrimSpace(out) != "" {
				t.Errorf("expected empty output, got: %s", out)
			}
			for _, s := range tt.wantSubstr {
				if !strings.Contains(out, s) {
					t.Errorf("output missing %q", s)
				}
			}
		})
	}
}

func TestPrintDualEngineTable_InvalidJSON(t *testing.T) {
	out := captureStdout(t, func() { printDualEngineTable([]byte("not json")) })
	if !strings.Contains(out, "not json") {
		t.Error("expected raw fallback output on invalid JSON")
	}
}

func TestNewCmd(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "dump" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "dump")
	}
	f := cmd.Flags().Lookup("output")
	if f == nil {
		t.Fatal("--output flag not defined")
	}
	if f.Shorthand != "o" {
		t.Errorf("--output shorthand = %q, want %q", f.Shorthand, "o")
	}
	if f.DefValue != "table" {
		t.Errorf("--output default = %q, want %q", f.DefValue, "table")
	}
}
