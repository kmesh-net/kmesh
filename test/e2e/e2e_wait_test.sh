#!/bin/bash
# Unit tests for test/e2e/e2e_wait.sh (issue #1956).
# Run: bash test/e2e/e2e_wait_test.sh
# Mocks kubectl/sleep so no cluster is needed.

set -u

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=e2e_wait.sh
source "$SCRIPT_DIR/e2e_wait.sh"

PASS=0
FAIL=0

function assert_eq() {
	local want="$1"
	local got="$2"
	local name="$3"
	if [ "$want" = "$got" ]; then
		PASS=$((PASS + 1))
		echo "PASS: $name"
	else
		FAIL=$((FAIL + 1))
		echo "FAIL: $name (want=$want got=$got)"
	fi
}

function assert_contains() {
	local haystack="$1"
	local needle="$2"
	local name="$3"
	if [[ $haystack == *"$needle"* ]]; then
		PASS=$((PASS + 1))
		echo "PASS: $name"
	else
		FAIL=$((FAIL + 1))
		echo "FAIL: $name (missing '$needle' in: $haystack)"
	fi
}

# No-op sleep to keep tests fast; elapsed time still advances via interval math.
function sleep() {
	:
}

# --- Test 1 (bug scenario): pods never become Running -> must fail fast, not hang ---
MOCK_PHASES_NEVER="Pending"
function kubectl() {
	if [[ $* == *"describe"* ]]; then
		echo "mock describe output"
		return 0
	fi
	if [[ $* == *"-o wide"* ]]; then
		echo "mock wide output"
		return 0
	fi
	echo "istiod-abc Pending"
}
out=$(wait_for_pods_by_phase "istio-system" "app=istiod" 3 1 2>&1)
rc=$?
assert_eq "1" "$rc" "never-running returns 1 (fails fast instead of hanging)"
assert_contains "$out" "timed out after 3s" "never-running prints actionable timeout"
assert_contains "$out" "kubectl get pods" "timeout dumps diagnostics"
unset -f kubectl

# --- Test 2 (edge): empty pod list must NOT succeed early (old setup_kmesh 0==0 bug) ---
# NOTE: $(...) runs in a subshell, so the mock must keep state in a file,
# not a shell variable (variables do not propagate back to the parent).
EMPTY_CALL_FILE=$(mktemp)
echo 0 >"$EMPTY_CALL_FILE"
function kubectl() {
	if [[ $* == *"describe"* || $* == *"-o wide"* ]]; then
		return 0
	fi
	n=$(cat "$EMPTY_CALL_FILE")
	n=$((n + 1))
	echo "$n" >"$EMPTY_CALL_FILE"
	if [ "$n" -lt 3 ]; then
		echo ""
	else
		echo "kmesh-xyz Running"
	fi
}
out=$(wait_for_pods_by_phase "kmesh-system" "app=kmesh" 10 1 2>&1)
rc=$?
assert_eq "0" "$rc" "empty-then-ready eventually succeeds"
assert_contains "$out" "are Running" "empty-then-ready prints success"
unset -f kubectl
rm -f "$EMPTY_CALL_FILE"

# --- Test 3 (regression): all Running immediately -> success ---
function kubectl() {
	return 0
}
# kubectl with no args match above prints nothing; override to print Running pods.
unset -f kubectl
function kubectl() {
	echo -e "pod-a Running\npod-b Running"
}
out=$(wait_for_pods_by_phase "kmesh-system" "app=kmesh" 10 1 2>&1)
rc=$?
assert_eq "0" "$rc" "all-running returns 0"
assert_contains "$out" "2 pod(s)" "all-running reports pod count"
unset -f kubectl

# --- Test 4 (edge): partial readiness then full readiness -> success ---
PARTIAL_CALL_FILE=$(mktemp)
echo 0 >"$PARTIAL_CALL_FILE"
function kubectl() {
	if [[ $* == *"describe"* || $* == *"-o wide"* ]]; then
		return 0
	fi
	n=$(cat "$PARTIAL_CALL_FILE")
	n=$((n + 1))
	echo "$n" >"$PARTIAL_CALL_FILE"
	if [ "$n" -lt 2 ]; then
		echo -e "pod-a Running\npod-b Pending"
	else
		echo -e "pod-a Running\npod-b Running"
	fi
}
out=$(wait_for_pods_by_phase "kmesh-system" "app=kmesh" 10 1 2>&1)
rc=$?
assert_eq "0" "$rc" "partial-then-ready returns 0"
rm -f "$PARTIAL_CALL_FILE"
unset -f kubectl

# --- Test 5 (regression): single pod Running (istiod shape) -> success ---
function kubectl() {
	echo "istiod-abc Running"
}
out=$(wait_for_pods_by_phase "istio-system" "app=istiod" 10 1 2>&1)
rc=$?
assert_eq "0" "$rc" "single-running returns 0"
unset -f kubectl

echo "----"
echo "PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -ne 0 ]; then
	echo "E2E wait helper tests FAILED"
	exit 1
fi
echo "E2E wait helper tests PASSED"
