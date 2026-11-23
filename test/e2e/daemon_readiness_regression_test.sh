#!/usr/bin/env bash

# Regression tests for the readiness-gated daemon setup and diagnostics
# collection in run_test.sh. They exercise collect_diagnostics() and
# setup_kmesh() as extracted verbatim from that file against a mocked
# kubectl/helm/kmeshctl, so they run without a real cluster.
#
# Scenarios:
#   1. Pods are Running but never report Ready -> setup fails and the
#      failure path dumps diagnostics before exiting.
#   2. Pods transition to Ready -> setup proceeds past the readiness gate.
#   3. Pods are Ready but the admin port refuses connections -> retries are
#      exhausted and the failure path dumps diagnostics before exiting.
#   4. collect_diagnostics gathers pods, events, pod description, restart
#      counts, current logs, and previous logs.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_TEST_SH="$SCRIPT_DIR/run_test.sh"

PASS=0
FAIL=0

function ok() {
	PASS=$((PASS + 1))
	echo "ok - $1"
}

function not_ok() {
	FAIL=$((FAIL + 1))
	echo "not ok - $1"
	if [ -n "${2:-}" ]; then
		echo "--- output ---"
		echo "$2"
		echo "--------------"
	fi
}

# Pull collect_diagnostics() and setup_kmesh() verbatim out of run_test.sh so
# these tests exercise the real production functions rather than a
# reimplementation of them.
function extract_functions_under_test() {
	awk '
		/^function collect_diagnostics\(\)/ { capture=1 }
		/^function setup_kmesh\(\)/ { capture=1 }
		capture { print }
		capture && /^}$/ { capture=0 }
	' "$RUN_TEST_SH"
}

FUNCTIONS_UNDER_TEST="$(extract_functions_under_test)"

if ! grep -q "^function collect_diagnostics" <<<"$FUNCTIONS_UNDER_TEST" ||
	! grep -q "^function setup_kmesh" <<<"$FUNCTIONS_UNDER_TEST"; then
	echo "FATAL: could not extract collect_diagnostics()/setup_kmesh() from $RUN_TEST_SH" >&2
	exit 1
fi

MOCK_BIN="$(mktemp -d)"
trap 'rm -rf "$MOCK_BIN"' EXIT

# helm/sleep are no-ops: this suite tests the readiness-gate and diagnostics
# logic, not helm installs or real retry delays.
cat >"$MOCK_BIN/helm" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"$MOCK_BIN/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

# Dispatches on the kubectl subcommand to emulate each scenario, driven by
# MOCK_* environment variables set per test case below.
cat >"$MOCK_BIN/kubectl" <<'EOF'
#!/usr/bin/env bash
args="$*"
case "$args" in
*"wait --for=condition=Ready"*)
	echo "${MOCK_WAIT_OUTPUT:-}"
	exit "${MOCK_WAIT_EXIT:-0}"
	;;
*"--no-headers"*)
	for _ in $(seq 1 "${MOCK_POD_COUNT:-1}"); do echo "${MOCK_POD_NAME:-kmesh-abc} Running"; done
	;;
*"-A -o wide"*)
	echo "DIAG_PODS_WIDE ${MOCK_POD_NAME:-kmesh-abc}"
	;;
*"get events"*)
	echo "DIAG_EVENTS ns=$3"
	;;
*"describe pod"*)
	echo "DIAG_DESCRIBE pod=$3"
	;;
*"restartCount"*)
	echo "${MOCK_POD_NAME:-kmesh-abc}  ready=true  restartCount=${MOCK_RESTART_COUNT:-0}"
	;;
*"--previous"*)
	echo "DIAG_LOGS_PREVIOUS pod=$2"
	;;
*"logs "*)
	echo "DIAG_LOGS_CURRENT pod=$2"
	;;
*"jsonpath={.items[*].metadata.name}"*)
	echo "${MOCK_POD_NAME:-kmesh-abc}"
	;;
*)
	echo "unmocked kubectl invocation: $args" >&2
	exit 1
	;;
esac
EOF

# Mirrors ctl/log/log.go: on a connection failure SetLoggerLevel logs the
# error and returns without calling os.Exit, so the real kmeshctl process
# exits 0 even though the operation failed. The caller in run_test.sh detects
# failure by grepping the output, not the exit code.
cat >"$MOCK_BIN/kmeshctl" <<'EOF'
#!/usr/bin/env bash
if [ "${MOCK_KMESHCTL_FAIL:-0}" = "1" ]; then
	echo "failed to make HTTP request: dial tcp 127.0.0.1:15200: connect: connection refused"
	exit 0
fi
case "$*" in
*"bpf:debug"*) echo "set BPF Log Level: 3" ;;
*"default:debug"*) echo "OK" ;;
esac
EOF

chmod +x "$MOCK_BIN"/*
export PATH="$MOCK_BIN:$PATH"

TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then
	TIMEOUT_CMD="timeout 15"
fi

# Runs setup_kmesh in an isolated subshell: on the failure paths it calls
# `exit` directly (it's written to run as a script, not a library function),
# so it must not run in this process. set -e is enabled to match how
# run_test.sh actually runs it.
function run_setup_kmesh() {
	$TIMEOUT_CMD bash -c '
		set -e
		'"$FUNCTIONS_UNDER_TEST"'
		setup_kmesh
	' 2>&1
}

function run_collect_diagnostics() {
	$TIMEOUT_CMD bash -c '
		'"$FUNCTIONS_UNDER_TEST"'
		collect_diagnostics "kmesh-system"
	' 2>&1
}

function test_running_but_not_ready() {
	export MOCK_POD_COUNT=1 MOCK_POD_NAME="kmesh-abc"
	export MOCK_WAIT_EXIT=1
	export MOCK_WAIT_OUTPUT="error: timed out waiting for the condition on pods/kmesh-abc"
	unset MOCK_KMESHCTL_FAIL

	local output rc
	output=$(run_setup_kmesh)
	rc=$?

	if [ "$rc" -ne 0 ] &&
		grep -q "did not become Ready" <<<"$output" &&
		grep -q "===== DIAGNOSTICS" <<<"$output" &&
		! grep -q "All pods of Kmesh daemon are Ready" <<<"$output"; then
		ok "setup_kmesh fails and dumps diagnostics when pods stay Running but never become Ready"
	else
		not_ok "setup_kmesh fails and dumps diagnostics when pods stay Running but never become Ready (rc=$rc)" "$output"
	fi
}

function test_ready_transition() {
	export MOCK_POD_COUNT=1 MOCK_POD_NAME="kmesh-abc"
	export MOCK_WAIT_EXIT=0 MOCK_WAIT_OUTPUT="pod/kmesh-abc condition met"
	unset MOCK_KMESHCTL_FAIL

	local output rc
	output=$(run_setup_kmesh)
	rc=$?

	if [ "$rc" -eq 0 ] &&
		grep -q "All pods of Kmesh daemon are Ready" <<<"$output" &&
		! grep -q "===== DIAGNOSTICS" <<<"$output"; then
		ok "setup_kmesh proceeds past the readiness gate once pods report Ready"
	else
		not_ok "setup_kmesh proceeds past the readiness gate once pods report Ready (rc=$rc)" "$output"
	fi
}

function test_connection_refused_exhausts_retries() {
	export MOCK_POD_COUNT=1 MOCK_POD_NAME="kmesh-abc"
	export MOCK_WAIT_EXIT=0 MOCK_WAIT_OUTPUT="pod/kmesh-abc condition met"
	export MOCK_KMESHCTL_FAIL=1

	local output rc
	output=$(run_setup_kmesh)
	rc=$?

	if [ "$rc" -ne 0 ] &&
		grep -q "connection refused" <<<"$output" &&
		grep -q "Failed to set BPF debug log after 5 attempts" <<<"$output" &&
		grep -q "===== DIAGNOSTICS" <<<"$output"; then
		ok "setup_kmesh exhausts retries and dumps diagnostics when kmeshctl reports connection refused"
	else
		not_ok "setup_kmesh exhausts retries and dumps diagnostics when kmeshctl reports connection refused (rc=$rc)" "$output"
	fi
	unset MOCK_KMESHCTL_FAIL
}

function test_collect_diagnostics_contents() {
	export MOCK_POD_NAME="kmesh-abc" MOCK_RESTART_COUNT=3

	local output missing=()
	output=$(run_collect_diagnostics)

	grep -q "DIAG_PODS_WIDE" <<<"$output" || missing+=("pod list")
	grep -q "DIAG_EVENTS" <<<"$output" || missing+=("events")
	grep -q "DIAG_DESCRIBE" <<<"$output" || missing+=("pod description")
	grep -q "restartCount=3" <<<"$output" || missing+=("restart count")
	grep -q "DIAG_LOGS_CURRENT" <<<"$output" || missing+=("current logs")
	grep -q "DIAG_LOGS_PREVIOUS" <<<"$output" || missing+=("previous logs")

	if [ ${#missing[@]} -eq 0 ]; then
		ok "collect_diagnostics gathers pods, events, description, restart counts, current and previous logs"
	else
		not_ok "collect_diagnostics missing: ${missing[*]}" "$output"
	fi
}

test_running_but_not_ready
test_ready_transition
test_connection_refused_exhausts_retries
test_collect_diagnostics_contents

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
