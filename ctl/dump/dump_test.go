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
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout runs f with os.Stdout redirected and returns what it printed.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	f()

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close pipe writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read captured output: %v", err)
	}
	return string(out)
}

func Test_uint32ToIPStr(t *testing.T) {
	tests := []struct {
		name string
		ip   uint32
		want string
	}{
		{
			name: "zero address",
			ip:   0,
			want: "0.0.0.0",
		},
		{
			name: "loopback",
			ip:   0x0100007F,
			want: "127.0.0.1",
		},
		{
			name: "private address",
			ip:   0x0100A8C0,
			want: "192.168.0.1",
		},
		{
			name: "broadcast",
			ip:   0xFFFFFFFF,
			want: "255.255.255.255",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := uint32ToIPStr(tt.ip); got != tt.want {
				t.Errorf("uint32ToIPStr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_printDualEngineTable(t *testing.T) {
	body := []byte(`{
		"workloads": [
			{
				"name": "sleep",
				"namespace": "default",
				"addresses": ["10.244.0.7", "10.244.0.8"],
				"protocol": "TCP",
				"status": "Healthy"
			}
		],
		"services": [
			{
				"name": "httpbin",
				"namespace": "default",
				"hostname": "httpbin.default.svc.cluster.local",
				"vips": ["10.96.0.10"]
			}
		],
		"policies": [
			{
				"name": "allow-nothing",
				"namespace": "default",
				"scope": "WORKLOAD_SELECTOR",
				"action": "DENY"
			}
		]
	}`)

	out := captureStdout(t, func() { printDualEngineTable(body) })

	for _, want := range []string{
		"NAME", "NAMESPACE", "ADDRESSES", "PROTOCOL", "STATUS",
		"sleep", "default", "10.244.0.7,10.244.0.8", "TCP", "Healthy",
		"HOSTNAME", "VIPS",
		"httpbin", "httpbin.default.svc.cluster.local", "10.96.0.10",
		"SCOPE", "ACTION",
		"allow-nothing", "WORKLOAD_SELECTOR", "DENY",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, out)
		}
	}
}

func Test_printDualEngineTableEmpty(t *testing.T) {
	out := captureStdout(t, func() { printDualEngineTable([]byte(`{}`)) })
	if strings.TrimSpace(out) != "" {
		t.Errorf("expected no output for an empty dump, got:\n%s", out)
	}
}

// A malformed body must not lose the operator's data: the raw response is
// printed instead of the table.
func Test_printDualEngineTableInvalidJSON(t *testing.T) {
	body := []byte(`not json at all`)
	out := captureStdout(t, func() { printDualEngineTable(body) })
	if !strings.Contains(out, "not json at all") {
		t.Errorf("expected raw body to be echoed, got:\n%s", out)
	}
}

func Test_printKernelNativeTable(t *testing.T) {
	body := []byte(`{
		"staticResources": {
			"clusterConfigs": [
				{"name": "outbound|80||httpbin.default.svc.cluster.local", "connectTimeout": 5}
			]
		},
		"dynamicResources": {
			"routeConfigs": [
				{
					"name": "http.80",
					"virtualHosts": [
						{"name": "httpbin.default.svc.cluster.local:80", "domains": ["httpbin", "httpbin.default"]}
					]
				}
			]
		}
	}`)

	out := captureStdout(t, func() { printKernelNativeTable(body) })

	for _, want := range []string{
		"NAME", "LB_POLICY", "CONNECT_TIMEOUT",
		"outbound|80||httpbin.default.svc.cluster.local",
		"ROUTE", "VIRTUAL_HOST", "DOMAINS",
		"http.80", "httpbin,httpbin.default",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, out)
		}
	}
}

func Test_printKernelNativeTableInvalidJSON(t *testing.T) {
	body := []byte(`{"staticResources": "should be an object"}`)
	out := captureStdout(t, func() { printKernelNativeTable(body) })
	if !strings.Contains(out, "should be an object") {
		t.Errorf("expected raw body to be echoed, got:\n%s", out)
	}
}
