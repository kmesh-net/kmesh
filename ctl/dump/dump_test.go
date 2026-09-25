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
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	adminv2 "kmesh.net/kmesh/api/v2/admin"
	"kmesh.net/kmesh/api/v2/cluster"
	"kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/api/v2/listener"
	"kmesh.net/kmesh/api/v2/route"
)

func TestUint32ToIPStr(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{name: "zero", ip: "0.0.0.0"},
		{name: "loopback", ip: "127.0.0.1"},
		{name: "private", ip: "192.168.1.10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := net.ParseIP(tt.ip).To4()
			if b == nil {
				t.Fatalf("invalid test IP %q", tt.ip)
			}
			v := binary.LittleEndian.Uint32(b)
			if got := uint32ToIPStr(v); got != tt.ip {
				t.Errorf("uint32ToIPStr(%d) = %q, want %q", v, got, tt.ip)
			}
		})
	}
}

func TestNewCmd(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "dump" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "dump")
	}
	if cmd.Args == nil {
		t.Fatal("Args validator not set")
	}

	root := &cobra.Command{Use: "kmeshctl"}
	root.AddCommand(cmd)
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"dump"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error for missing args")
	}

	flag := cmd.Flags().Lookup("output")
	if flag == nil {
		t.Fatal("--output flag not defined")
	}
	if flag.Shorthand != "o" {
		t.Errorf("output shorthand = %q, want %q", flag.Shorthand, "o")
	}
	if flag.DefValue != "table" {
		t.Errorf("output default = %q, want %q", flag.DefValue, "table")
	}
}

func TestPrintKernelNativeTable(t *testing.T) {
	t.Run("renders clusters listeners routes", func(t *testing.T) {
		ip := net.ParseIP("10.0.0.1").To4()
		dump := &adminv2.ConfigDump{
			StaticResources: &adminv2.ConfigResources{
				ClusterConfigs: []*cluster.Cluster{
					{
						Name:           "outbound|80||svc.default.svc.cluster.local",
						LbPolicy:       cluster.Cluster_ROUND_ROBIN,
						ConnectTimeout: 5,
					},
				},
				ListenerConfigs: []*listener.Listener{
					{
						Name: "listener-1",
						Address: &core.SocketAddress{
							Ipv4: binary.LittleEndian.Uint32(ip),
							Port: 15001,
						},
						FilterChains: []*listener.FilterChain{
							{Name: "fc-a"},
							{Name: "fc-b"},
						},
					},
					{
						Name: "listener-no-addr",
					},
				},
				RouteConfigs: []*route.RouteConfiguration{
					{
						Name: "route-1",
						VirtualHosts: []*route.VirtualHost{
							{Name: "vh-1", Domains: []string{"example.com", "www.example.com"}},
						},
					},
				},
			},
			DynamicResources: &adminv2.ConfigResources{
				ClusterConfigs: []*cluster.Cluster{
					{
						Name:           "dynamic-cluster",
						LbPolicy:       cluster.Cluster_RANDOM,
						ConnectTimeout: 3,
					},
				},
			},
		}
		body, err := protojson.Marshal(dump)
		if err != nil {
			t.Fatalf("marshal config dump: %v", err)
		}

		out := captureStdout(t, func() {
			printKernelNativeTable(body)
		})

		for _, want := range []string{
			"NAME", "LB_POLICY", "CONNECT_TIMEOUT",
			"outbound|80||svc.default.svc.cluster.local", "ROUND_ROBIN", "5",
			"dynamic-cluster", "RANDOM", "3",
			"ADDRESS", "PORT", "FILTER_CHAINS",
			"listener-1", "10.0.0.1", "15001", "fc-a,fc-b",
			"listener-no-addr", "-",
			"ROUTE", "VIRTUAL_HOST", "DOMAINS",
			"route-1", "vh-1", "example.com,www.example.com",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("output missing %q\n%s", want, out)
			}
		}
	})

	t.Run("invalid json falls back to raw", func(t *testing.T) {
		raw := "not-valid-protojson"
		out := captureStdout(t, func() {
			printKernelNativeTable([]byte(raw))
		})
		if !strings.Contains(out, raw) {
			t.Errorf("fallback output missing raw body\n%s", out)
		}
	})
}

func TestPrintDualEngineTable(t *testing.T) {
	t.Run("renders workloads services policies", func(t *testing.T) {
		body := []byte(`{
			"workloads": [{
				"name": "pod-a",
				"namespace": "default",
				"addresses": ["10.1.0.2", "10.1.0.3"],
				"protocol": "TCP",
				"status": "Healthy"
			}],
			"services": [{
				"name": "svc-a",
				"namespace": "default",
				"hostname": "svc-a.default.svc.cluster.local",
				"vips": ["10.96.0.10"]
			}],
			"policies": [{
				"name": "allow-all",
				"namespace": "default",
				"scope": "NAMESPACE",
				"action": "ALLOW"
			}]
		}`)

		out := captureStdout(t, func() {
			printDualEngineTable(body)
		})

		for _, want := range []string{
			"NAME", "NAMESPACE", "ADDRESSES", "PROTOCOL", "STATUS",
			"pod-a", "default", "10.1.0.2,10.1.0.3", "TCP", "Healthy",
			"HOSTNAME", "VIPS",
			"svc-a", "svc-a.default.svc.cluster.local", "10.96.0.10",
			"SCOPE", "ACTION",
			"allow-all", "NAMESPACE", "ALLOW",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("output missing %q\n%s", want, out)
			}
		}
	})

	t.Run("invalid json falls back to raw", func(t *testing.T) {
		raw := "not-valid-json"
		out := captureStdout(t, func() {
			printDualEngineTable([]byte(raw))
		})
		if !strings.Contains(out, raw) {
			t.Errorf("fallback output missing raw body\n%s", out)
		}
	})
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()

	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	_ = w.Close()
	return <-done
}
