package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseBenchmarkOutput(t *testing.T) {
	t.Parallel()

	output := `goos: linux
goarch: amd64
pkg: kmesh.net/kmesh/pkg/cache/v2
cpu: Intel(R) Xeon(R)
BenchmarkClusterFlush-8   	       1	835615271 ns/op	  2048 B/op	      18 allocs/op
BenchmarkListenerFlush-8  	       1	100000000 ns/op
PASS
ok  	kmesh.net/kmesh/pkg/cache/v2	0.123s
`

	path := filepath.Join(t.TempDir(), "bench.txt")
	if err := os.WriteFile(path, []byte(output), 0o600); err != nil {
		t.Fatalf("write benchmark output: %v", err)
	}

	results, err := parseBenchmarkOutput(path)
	if err != nil {
		t.Fatalf("parse benchmark output: %v", err)
	}

	clusterResult, found := results[resultKey("kmesh.net/kmesh/pkg/cache/v2", "BenchmarkClusterFlush")]
	if !found {
		t.Fatalf("cluster benchmark result missing")
	}
	if clusterResult.NsPerOp != 835615271 {
		t.Fatalf("unexpected cluster ns/op: got %d", clusterResult.NsPerOp)
	}

	listenerResult, found := results[resultKey("kmesh.net/kmesh/pkg/cache/v2", "BenchmarkListenerFlush")]
	if !found {
		t.Fatalf("listener benchmark result missing")
	}
	if listenerResult.NsPerOp != 100000000 {
		t.Fatalf("unexpected listener ns/op: got %d", listenerResult.NsPerOp)
	}
}

func TestEvaluateThresholds(t *testing.T) {
	t.Parallel()

	thresholds := []threshold{
		{
			Package:    "kmesh.net/kmesh/pkg/cache/v2",
			Benchmark:  "BenchmarkClusterFlush",
			MaxNsPerOp: 500,
		},
		{
			Package:    "kmesh.net/kmesh/pkg/cache/v2",
			Benchmark:  "BenchmarkListenerFlush",
			MaxNsPerOp: 200,
		},
	}
	results := map[string]benchmarkResult{
		resultKey("kmesh.net/kmesh/pkg/cache/v2", "BenchmarkClusterFlush"): {
			Package:   "kmesh.net/kmesh/pkg/cache/v2",
			Benchmark: "BenchmarkClusterFlush",
			NsPerOp:   400,
		},
	}

	failures := evaluateThresholds(thresholds, results)
	if len(failures) != 1 {
		t.Fatalf("unexpected number of failures: got %d, want 1", len(failures))
	}
}
