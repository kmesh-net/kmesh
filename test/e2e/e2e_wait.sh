#!/bin/bash

# Helpers for E2E setup waits.
#
# Background (see https://github.com/kmesh-net/kmesh/issues/1956):
# setup_istio/setup_kmesh in run_test.sh used `while true` loops without any
# timeout. If a pod never reaches Running, the job hangs until GitHub's
# `timeout-minutes: 40` kills it, producing unactionable cancellations.
# These helpers bound every wait and dump diagnostics on timeout so failures
# are actionable.

E2E_WAIT_TIMEOUT=${E2E_WAIT_TIMEOUT:-300}
E2E_WAIT_INTERVAL=${E2E_WAIT_INTERVAL:-5}

# Wait until every pod matching label in namespace has phase Running.
# Args: namespace label [timeout_seconds [interval_seconds]]
# Returns 0 on success, 1 on timeout. Requires at least one pod.
function wait_for_pods_by_phase() {
	local namespace="${1:?namespace is required}"
	local label="${2:?label is required}"
	local timeout="${3:-$E2E_WAIT_TIMEOUT}"
	local interval="${4:-$E2E_WAIT_INTERVAL}"
	local elapsed=0
	local pod_statuses
	local total_pods
	local running_pods
	local line
	local pod_name
	local pod_status

	while [ "$elapsed" -lt "$timeout" ]; do
		pod_statuses=$(kubectl get pods -n "$namespace" -l "$label" -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.phase}{"\n"}{end}' 2>/dev/null || true)

		total_pods=0
		running_pods=0
		while IFS= read -r line; do
			[ -z "$line" ] && continue
			total_pods=$((total_pods + 1))
			read -r pod_name pod_status <<<"$line"
			if [ "$pod_status" = "Running" ]; then
				running_pods=$((running_pods + 1))
			fi
		done <<<"$pod_statuses"

		if [ "$total_pods" -gt 0 ] && [ "$running_pods" -eq "$total_pods" ]; then
			echo "All $total_pods pod(s) in namespace $namespace with label $label are Running."
			return 0
		fi

		echo "Waiting for pods in namespace $namespace with label $label to be Running ($running_pods/$total_pods Running, ${elapsed}s/${timeout}s)..."
		sleep "$interval"
		elapsed=$((elapsed + interval))
	done

	echo "ERROR: timed out after ${timeout}s waiting for pods in namespace $namespace with label $label to be Running." >&2
	echo "---- kubectl get pods -n $namespace -l $label -o wide ----" >&2
	kubectl get pods -n "$namespace" -l "$label" -o wide >&2 || true
	echo "---- kubectl describe pods -n $namespace -l $label ----" >&2
	kubectl describe pods -n "$namespace" -l "$label" >&2 || true
	return 1
}
