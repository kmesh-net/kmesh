#!/bin/bash
# Copyright The Kmesh Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# End-to-end smoke test for the Kmesh MCP server.
#
# Prerequisites:
#   - a running Kubernetes cluster with Kmesh (and Istio ambient) installed
#   - kubectl configured to reach the cluster
#   - go, python3 and curl in PATH
#
# Usage:
#   hack/mcp-e2e-smoke.sh
#
# Optional environment variables:
#   KMESH_NAMESPACE  namespace of the Kmesh daemon (default: kmesh-system)
#   MESH_NAMESPACE   namespace of the demo workloads (default: bookinfo)
#   WAYPOINT_NAME    waypoint gateway to inspect (default: waypoint)
#   DIAG_SOURCE      source for diagnose_connectivity (default: productpage)
#   DIAG_TARGET      target for diagnose_connectivity (default: reviews)

set -u

KMESH_NAMESPACE=${KMESH_NAMESPACE:-kmesh-system}
MESH_NAMESPACE=${MESH_NAMESPACE:-bookinfo}
WAYPOINT_NAME=${WAYPOINT_NAME:-waypoint}
DIAG_SOURCE=${DIAG_SOURCE:-productpage}
DIAG_TARGET=${DIAG_TARGET:-reviews}
SSE_ADDR=${SSE_ADDR:-http://localhost:8080}

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHECKER="$ROOT/hack/mcp_e2e_check.py"
TMP=$(mktemp -d)
SERVER_PID=""
CURL_PID=""

cleanup() {
	[ -n "$CURL_PID" ] && kill "$CURL_PID" 2>/dev/null
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
	rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

command -v go >/dev/null 2>&1 || fail "go not found in PATH"
command -v python3 >/dev/null 2>&1 || fail "python3 not found in PATH"
command -v kubectl >/dev/null 2>&1 || fail "kubectl not found in PATH"
command -v curl >/dev/null 2>&1 || fail "curl not found in PATH"

echo "==> Building kmeshctl"
BIN="$TMP/kmeshctl"
(cd "$ROOT" && go build -o "$BIN" ./ctl) || fail "build failed"

echo "==> Checking cluster access"
kubectl get namespace "$KMESH_NAMESPACE" >/dev/null 2>&1 ||
	fail "cannot reach the cluster (namespace $KMESH_NAMESPACE)"
kubectl -n "$KMESH_NAMESPACE" get pods -l app=kmesh >/dev/null 2>&1 ||
	fail "cannot list Kmesh daemon pods in namespace $KMESH_NAMESPACE"

echo "==> STDIO transport"
{
	printf '%s\n' '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"kmesh-e2e","version":"1.0"}}}'
	printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
	printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

	id=10
	call() {
		printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":$id,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}"
		id=$((id + 1))
	}

	call get_version '{}'
	call list_daemon_pods '{}'
	call get_daemon_health '{}'
	call get_mesh_namespaces '{}'
	call list_mesh_services '{}'
	call config_dump '{}'
	call get_bpf_maps '{}'
	call get_bpf_workload_details '{}'
	call get_bpf_ads_details '{}'
	call get_logger_levels '{}'
	call list_waypoints '{"allNamespaces":true}'
	call get_waypoint_status "{\"name\":\"$WAYPOINT_NAME\",\"namespace\":\"$MESH_NAMESPACE\"}"
	call get_authz_status '{}'
	call get_ipsec_status '{}'
	call diagnose_connectivity "{\"source\":\"$DIAG_SOURCE\",\"target\":\"$DIAG_TARGET\"}"
	call get_bpf_maps '{"mode":"invalid-mode"}'

	# Wait for the last response instead of guessing a fixed delay.
	for _ in $(seq 1 120); do
		grep -q '"id":25' "$TMP/stdio.out" 2>/dev/null && break
		sleep 0.5
	done
} | timeout 120 "$BIN" mcp serve >"$TMP/stdio.out" 2>"$TMP/stdio.err"

python3 "$CHECKER" stdio "$TMP/stdio.out" || fail "stdio transport checks failed"

echo "==> SSE transport"
"$BIN" mcp serve --transport sse >"$TMP/sse-server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 20); do
	grep -q "running on SSE" "$TMP/sse-server.log" 2>/dev/null && break
	sleep 0.5
done
grep -q "running on SSE" "$TMP/sse-server.log" 2>/dev/null || fail "SSE server did not start"

curl -N -s "$SSE_ADDR/sse" >"$TMP/sse.out" 2>/dev/null &
CURL_PID=$!
SID=""
for _ in $(seq 1 20); do
	SID=$(grep -o 'sessionId=[a-zA-Z0-9-]*' "$TMP/sse.out" 2>/dev/null | head -1 | cut -d= -f2)
	[ -n "$SID" ] && break
	sleep 0.5
done
[ -n "$SID" ] || fail "no SSE session id received"

post() {
	curl -s -X POST "$SSE_ADDR/message?sessionId=$SID" \
		-H 'Content-Type: application/json' -d "$1" >/dev/null
}
post '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"kmesh-e2e","version":"1.0"}}}'
post '{"jsonrpc":"2.0","method":"notifications/initialized"}'
post '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
post '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_version","arguments":{}}}'
post '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_mesh_namespaces","arguments":{}}}'
for _ in $(seq 1 60); do
	grep -q '"id":4' "$TMP/sse.out" 2>/dev/null && break
	sleep 0.5
done

python3 "$CHECKER" sse "$TMP/sse.out" || fail "SSE transport checks failed"

echo "MCP end-to-end smoke test PASSED"
