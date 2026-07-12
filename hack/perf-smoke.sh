#!/bin/bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/.artifacts/perf-smoke}"
CONFIG_FILE="${CONFIG_FILE:-$ROOT_DIR/.github/performance/smoke-thresholds.json}"

required_objects=(
	"$ROOT_DIR/bpf/kmesh/bpf2go/kernelnative/normal/kmeshcgroupsock_bpfel.o"
	"$ROOT_DIR/bpf/kmesh/bpf2go/general/kmeshtcmarkdecrypt_bpfel.o"
	"$ROOT_DIR/bpf/kmesh/bpf2go/dualengine/kmeshcgroupskb_bpfel.o"
)

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
	echo "performance smoke benchmarks require root to initialize BPF maps" >&2
	echo "run with: sudo env PATH=\$PATH PKG_CONFIG_PATH=$ROOT_DIR/mk LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:$ROOT_DIR/api/v2-c:$ROOT_DIR/bpf/deserialization_to_bpf_map make perf-smoke" >&2
	exit 1
fi

for object_file in "${required_objects[@]}"; do
	if [[ ! -f "$object_file" ]]; then
		echo "missing generated benchmark prerequisite: $object_file" >&2
		echo "run: sudo env PATH=\$PATH bash ./build.sh" >&2
		exit 1
	fi
done

mkdir -p "$RESULTS_DIR"

export PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-$ROOT_DIR/mk}"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}:$ROOT_DIR/api/v2-c:$ROOT_DIR/bpf/deserialization_to_bpf_map"

run_benchmark() {
	local package_path="$1"
	local bench_filter="$2"
	local output_file="$3"

	go test "$package_path" \
		-run '^$' \
		-bench "$bench_filter" \
		-benchtime=1x \
		-benchmem | tee "$output_file"
}

run_benchmark ./pkg/cache/v2 '^(BenchmarkClusterFlush|BenchmarkListenerFlush)$' "$RESULTS_DIR/pkg-cache-v2.txt"
run_benchmark ./pkg/controller/workload '^BenchmarkAddNewServicesWithWorkload$' "$RESULTS_DIR/pkg-controller-workload.txt"

go run ./tools/perfcheck \
	-config "$CONFIG_FILE" \
	-input "$RESULTS_DIR/pkg-cache-v2.txt" \
	-input "$RESULTS_DIR/pkg-controller-workload.txt" | tee "$RESULTS_DIR/summary.txt"
