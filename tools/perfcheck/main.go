package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type threshold struct {
	Package     string `json:"package"`
	Benchmark   string `json:"benchmark"`
	MaxNsPerOp  int64  `json:"max_ns_per_op"`
	Description string `json:"description"`
}

type benchmarkResult struct {
	Package   string
	Benchmark string
	NsPerOp   int64
	RawLine   string
}

var benchmarkLineRE = regexp.MustCompile(`^(Benchmark\S+?)(?:-\d+)?\s+\d+\s+([0-9]+(?:\.[0-9]+)?)\s+ns/op(?:\s+.*)?$`)

func main() {
	var configPath string
	var inputFiles multiFlag

	flag.StringVar(&configPath, "config", "", "path to threshold config")
	flag.Var(&inputFiles, "input", "benchmark output file (repeatable)")
	flag.Parse()

	if configPath == "" || len(inputFiles) == 0 {
		fmt.Fprintln(os.Stderr, "usage: perfcheck -config <file> -input <benchmark-output> [-input <benchmark-output>]")
		os.Exit(2)
	}

	thresholds, err := loadThresholds(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load thresholds: %v\n", err)
		os.Exit(1)
	}

	results, err := loadResults(inputFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load benchmark results: %v\n", err)
		os.Exit(1)
	}

	failures := evaluateThresholds(thresholds, results)
	if len(failures) != 0 {
		for _, failure := range failures {
			fmt.Fprintf(os.Stderr, "FAIL: %s\n", failure)
		}
		os.Exit(1)
	}

	keys := make([]string, 0, len(results))
	for key := range results {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		result := results[key]
		fmt.Printf("PASS: %s %s = %d ns/op\n", result.Package, result.Benchmark, result.NsPerOp)
	}
}

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func loadThresholds(path string) ([]threshold, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var thresholds []threshold
	if err := json.Unmarshal(content, &thresholds); err != nil {
		return nil, err
	}

	return thresholds, nil
}

func loadResults(paths []string) (map[string]benchmarkResult, error) {
	results := make(map[string]benchmarkResult)
	for _, path := range paths {
		fileResults, err := parseBenchmarkOutput(path)
		if err != nil {
			return nil, err
		}
		for key, result := range fileResults {
			results[key] = result
		}
	}
	return results, nil
}

func parseBenchmarkOutput(path string) (map[string]benchmarkResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	results := make(map[string]benchmarkResult)
	scanner := bufio.NewScanner(file)
	currentPackage := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "pkg: ") {
			currentPackage = strings.TrimPrefix(line, "pkg: ")
			continue
		}

		matches := benchmarkLineRE.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		if currentPackage == "" {
			return nil, fmt.Errorf("%s: benchmark line found before pkg header", path)
		}

		nsPerOp, err := parseNsPerOp(matches[2])
		if err != nil {
			return nil, fmt.Errorf("%s: parse ns/op from %q: %w", path, line, err)
		}

		result := benchmarkResult{
			Package:   currentPackage,
			Benchmark: matches[1],
			NsPerOp:   nsPerOp,
			RawLine:   line,
		}
		results[resultKey(result.Package, result.Benchmark)] = result
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

func parseNsPerOp(value string) (int64, error) {
	if !strings.Contains(value, ".") {
		return strconv.ParseInt(value, 10, 64)
	}

	floatValue, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, err
	}
	return int64(floatValue), nil
}

func evaluateThresholds(thresholds []threshold, results map[string]benchmarkResult) []string {
	var failures []string

	for _, threshold := range thresholds {
		key := resultKey(threshold.Package, threshold.Benchmark)
		result, found := results[key]
		if !found {
			failures = append(failures, fmt.Sprintf("%s %s missing from benchmark output", threshold.Package, threshold.Benchmark))
			continue
		}

		if result.NsPerOp > threshold.MaxNsPerOp {
			label := threshold.Description
			if label == "" {
				label = threshold.Benchmark
			}
			failures = append(failures, fmt.Sprintf("%s exceeded threshold: got %d ns/op, want <= %d ns/op", label, result.NsPerOp, threshold.MaxNsPerOp))
		}
	}

	return failures
}

func resultKey(pkg, benchmark string) string {
	return pkg + "::" + benchmark
}
