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

package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const (
	// Envoy ConfigDump shape (kernel-native config_dump and bpf dump)
	envoyDump = `{"dynamicResources": {
		"listenerConfigs": [
			{"name": "listener-0", "address": {"socketAddress": {"address": "0.0.0.0", "portValue": 80}}},
			{"name": "listener-1", "address": {"socketAddress": {"address": "0.0.0.0", "portValue": 443}}}
		],
		"clusterConfigs": [
			{"name": "productpage", "type": "EDS"},
			{"name": "reviews", "type": "EDS"}
		]
	}}`

	// WorkloadDump shape (dual-engine config_dump)
	workloadDump = `{
		"workloads": [
			{"name": "sleep-abc", "namespace": "default", "addresses": ["10.0.0.1"], "status": "healthy"},
			{"name": "productpage-xyz", "namespace": "default", "addresses": ["10.0.0.2"], "status": "healthy"}
		],
		"services": [
			{"name": "productpage", "namespace": "default", "hostnames": ["productpage.default.svc.cluster.local"]}
		],
		"policies": []
	}`

	// WorkloadBpfDump shape (dual-engine bpf dump)
	bpfWorkloadDump = `{
		"frontends": [{"upstreamId": "default/sleep"}],
		"backends": [{"ip": "10.0.0.1", "serviceCount": 1, "services": ["default/productpage"]}],
		"endpoints": [{"backendUid": "default/sleep-abc"}]
	}`
)

func TestReadAllLimited(t *testing.T) {
	t.Run("under limit", func(t *testing.T) {
		data, err := readAllLimited(strings.NewReader("hello"), 10)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) != "hello" {
			t.Fatalf("got %q", data)
		}
	})

	t.Run("exactly at limit", func(t *testing.T) {
		data, err := readAllLimited(strings.NewReader("hello"), 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) != "hello" {
			t.Fatalf("got %q", data)
		}
	})

	t.Run("over limit", func(t *testing.T) {
		_, err := readAllLimited(strings.NewReader("hello world"), 5)
		if err == nil || !strings.Contains(err.Error(), errDumpTooLarge.Error()) {
			t.Fatalf("expected errDumpTooLarge, got %v", err)
		}
	})
}

func TestFormatDumpSummary(t *testing.T) {
	for name, raw := range map[string]string{
		"envoy":    envoyDump,
		"workload": workloadDump,
		"bpf":      bpfWorkloadDump,
	} {
		t.Run(name, func(t *testing.T) {
			out, err := formatDump([]byte(raw), "", true)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var parsed summaryOutput
			if err := json.Unmarshal([]byte(out), &parsed); err != nil {
				t.Fatalf("summary is not valid JSON: %v", err)
			}
			if !parsed.Summary {
				t.Fatal("expected summary=true")
			}
			if len(parsed.Counts) == 0 {
				t.Fatal("expected non-empty counts")
			}
			for cat, n := range parsed.Counts {
				if len(parsed.Categories[cat]) != n {
					t.Fatalf("category %q: count %d but %d items", cat, n, len(parsed.Categories[cat]))
				}
			}
		})
	}
}

func TestFormatDumpSummaryReducesSize(t *testing.T) {
	// Simulate a realistic dump: many items with verbose fields.
	var b strings.Builder
	b.WriteString(`{"workloads": [`)
	for i := 0; i < 200; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"name": "pod-%d", "namespace": "default", "uid": "uid-%d", "labels": {"app": "test", "version": "v1"}, "annotations": {"%s": "%s"}}`,
			i, i, strings.Repeat("key", 20), strings.Repeat("val", 40))
	}
	b.WriteString(`]}`)
	raw := b.String()

	out, err := formatDump([]byte(raw), "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Summary must stay compact even when the raw dump is huge.
	if len(out) > len(raw)/10 {
		t.Fatalf("summary (%d bytes) not meaningfully smaller than raw (%d bytes)", len(out), len(raw))
	}
}

func TestFormatDumpSummaryOmitsOverCap(t *testing.T) {
	// Build a dump with more items than maxSummaryItems.
	var b strings.Builder
	b.WriteString(`{"workloads": [`)
	total := maxSummaryItems + 7
	for i := 0; i < total; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"name": "pod-%d", "namespace": "default"}`, i)
	}
	b.WriteString(`]}`)

	out, err := formatDump([]byte(b.String()), "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed summaryOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed.Counts["workloads"] != total {
		t.Fatalf("expected count %d, got %d", total, parsed.Counts["workloads"])
	}
	if len(parsed.Categories["workloads"]) != maxSummaryItems {
		t.Fatalf("expected %d items, got %d", maxSummaryItems, len(parsed.Categories["workloads"]))
	}
	if parsed.Omitted["workloads"] != 7 {
		t.Fatalf("expected 7 omitted, got %d", parsed.Omitted["workloads"])
	}
}

func TestFormatDumpFilter(t *testing.T) {
	t.Run("matches by name, case-insensitive", func(t *testing.T) {
		out, err := formatDump([]byte(envoyDump), "PRODUCTPAGE", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var parsed filteredOutput
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if parsed.MatchCount != 1 {
			t.Fatalf("expected 1 match, got %d", parsed.MatchCount)
		}
		got := string(parsed.Matches["dynamicResources.clusterConfigs"][0])
		if !strings.Contains(got, `"EDS"`) || !strings.Contains(got, `"type"`) {
			t.Fatalf("expected full item JSON, got: %s", got)
		}
	})

	t.Run("matches by IP", func(t *testing.T) {
		out, err := formatDump([]byte(workloadDump), "10.0.0.2", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var parsed filteredOutput
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if parsed.MatchCount != 1 {
			t.Fatalf("expected 1 match, got %d", parsed.MatchCount)
		}
	})

	t.Run("no matches", func(t *testing.T) {
		out, err := formatDump([]byte(workloadDump), "nonexistent", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var parsed filteredOutput
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if parsed.MatchCount != 0 || parsed.Hint == "" {
			t.Fatalf("expected 0 matches with a hint, got %+v", parsed)
		}
	})

	t.Run("truncates at item boundaries", func(t *testing.T) {
		orig := maxResultBytes
		maxResultBytes = 256 // shrink cap for the test
		defer func() { maxResultBytes = orig }()

		var b strings.Builder
		b.WriteString(`{"clusters": [`)
		for i := 0; i < 5; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"name": "match-%d", "payload": "%s"}`, i, strings.Repeat("x", 120))
		}
		b.WriteString(`]}`)

		out, err := formatDump([]byte(b.String()), "match-", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var parsed filteredOutput
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("truncated output is not valid JSON: %v", err)
		}
		if parsed.MatchCount != 5 {
			t.Fatalf("expected 5 matches, got %d", parsed.MatchCount)
		}
		if !parsed.Truncated {
			t.Fatal("expected truncated=true")
		}
		if len(parsed.Matches["clusters"]) >= 5 {
			t.Fatal("expected fewer returned items than matches")
		}
	})
}

func TestFormatDumpRaw(t *testing.T) {
	t.Run("summary=false passes raw through", func(t *testing.T) {
		out, err := formatDump([]byte(envoyDump), "", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != envoyDump {
			t.Fatal("expected raw passthrough")
		}
	})

	t.Run("oversized raw is capped with marker", func(t *testing.T) {
		orig := maxResultBytes
		maxResultBytes = 64
		defer func() { maxResultBytes = orig }()

		out, err := formatDump([]byte(envoyDump), "", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "WARNING: TRUNCATED") {
			t.Fatal("expected truncation warning")
		}
	})

	t.Run("non-JSON payload falls back to byte cap", func(t *testing.T) {
		out, err := formatDump([]byte("plain text response"), "", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != "plain text response" {
			t.Fatalf("got %q", out)
		}
	})
}
