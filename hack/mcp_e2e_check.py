#!/usr/bin/env python3
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

"""Checks MCP JSON-RPC responses captured by hack/mcp-e2e-smoke.sh."""

import json
import sys

EXPECTED_TOOLS = {
    "get_version", "list_daemon_pods", "get_daemon_health", "get_mesh_namespaces",
    "list_mesh_services", "config_dump", "get_bpf_maps", "get_bpf_workload_details",
    "get_bpf_ads_details", "get_logger_levels", "list_waypoints",
    "get_waypoint_status", "get_authz_status", "get_ipsec_status",
    "diagnose_connectivity",
}

# stdio call ids and their tool names, in the order sent by the shell script.
STDIO_CALLS = {
    10: "get_version",
    11: "list_daemon_pods",
    12: "get_daemon_health",
    13: "get_mesh_namespaces",
    14: "list_mesh_services",
    15: "config_dump",
    16: "get_bpf_maps",
    17: "get_bpf_workload_details",
    18: "get_bpf_ads_details",
    19: "get_logger_levels",
    20: "list_waypoints",
    21: "get_waypoint_status",
    22: "get_authz_status",
    23: "get_ipsec_status",
    24: "diagnose_connectivity",
    25: "get_bpf_maps(invalid mode)",
}


def load_messages(path, sse):
    messages = {}
    with open(path, errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if sse:
                if not line.startswith("data:"):
                    continue
                payload = line[len("data:"):].strip()
            else:
                if not line.startswith("{"):
                    continue
                payload = line
            try:
                message = json.loads(payload)
            except ValueError:
                continue
            if isinstance(message.get("id"), int):
                messages[message["id"]] = message.get("result") or {}
    return messages


def text_of(result):
    content = result.get("content") or []
    if not content:
        return ""
    return content[0].get("text", "")


def is_error(result):
    return bool(result.get("isError"))


def check_tools_list(result, failures):
    tools = {tool.get("name") for tool in result.get("tools", [])}
    missing = EXPECTED_TOOLS - tools
    if missing:
        failures.append(f"tools/list missing tools: {sorted(missing)}")
        return
    if len(tools) != len(EXPECTED_TOOLS):
        failures.append(f"tools/list returned {len(tools)} tools, expected {len(EXPECTED_TOOLS)}")


def mode_from(result, failures):
    text = text_of(result)
    for mode in ("dual-engine", "kernel-native"):
        if f'"mode": "{mode}"' in text:
            return mode
    failures.append(f"get_version did not report a daemon mode: {text[:120]!r}")
    return "dual-engine"


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("stdio", "sse"):
        print("usage: mcp_e2e_check.py <stdio|sse> <responses-file>", file=sys.stderr)
        return 2
    transport, path = sys.argv[1], sys.argv[2]
    messages = load_messages(path, sse=(transport == "sse"))
    failures = []
    passed = 0

    if transport == "sse":
        if 1 not in messages:
            failures.append("initialize: no response")
        else:
            passed += 1  # initialize result shape is not asserted further
        if 2 not in messages:
            failures.append("tools/list: no response")
        else:
            check_tools_list(messages[2], failures)
            passed += 1
        for call_id, name in ((3, "get_version"), (4, "get_mesh_namespaces")):
            if call_id not in messages:
                failures.append(f"{name}: no response")
            elif is_error(messages[call_id]):
                failures.append(f"{name}: unexpected tool error: {text_of(messages[call_id])[:160]!r}")
            else:
                passed += 1
    else:
        if 1 not in messages:
            failures.append("tools/list: no response")
            mode = "dual-engine"
        else:
            check_tools_list(messages[1], failures)
            passed += 1
            mode = mode_from(messages[10], failures) if 10 in messages else "dual-engine"

        for call_id, name in STDIO_CALLS.items():
            if call_id not in messages:
                failures.append(f"{name}: no response")
                continue
            result = messages[call_id]
            errored = is_error(result)
            text = text_of(result)

            if name in ("get_bpf_workload_details", "get_bpf_ads_details"):
                # The tool matching the daemon mode must succeed; the other is
                # expected to fail with a pointer to its sibling.
                wants_error = (mode == "dual-engine") == (name == "get_bpf_ads_details")
            elif name == "get_bpf_maps(invalid mode)":
                wants_error = True
            elif name == "get_waypoint_status":
                # A missing waypoint is a valid result for a smoke test.
                wants_error = errored and "not found" in text
                if wants_error:
                    passed += 1
                    continue
            else:
                wants_error = False

            if errored != wants_error:
                failures.append(f"{name}: isError={errored}, expected {wants_error}: {text[:160]!r}")
                continue
            if name == "diagnose_connectivity" and "verdict" not in text:
                failures.append(f"diagnose_connectivity: response has no verdict: {text[:160]!r}")
                continue
            passed += 1

    total = passed + len(failures)
    for failure in failures:
        print(f"FAIL  {failure}")
    print(f"--- {transport}: {passed}/{total} checks passed ---")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
