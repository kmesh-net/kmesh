# Kmesh MCP Tools Reference

The Kmesh MCP server (`kmeshctl mcp serve`) exposes Kmesh internals as tools for
AI agents (Claude Desktop, Cursor, Copilot). This page lists every tool: what it
does, what it takes, and where its data comes from.

## How tools fetch data

```text
AI client ──MCP (stdio or SSE :8080)──► kmeshctl mcp serve
                                          │
              ┌───────────────────────────┴────────────────────────────┐
              │ Kubernetes API (list/get)        port-forward → daemon │
              │ pods, namespaces, services,      localhost:15200       │
              │ gateways, secrets                status server         │
              └────────────────────────────────────────────────────────┘
```

- **Daemon tools** open a short-lived port-forward to the kmesh-daemon pod and
  query its status server on port 15200. The pod is auto-discovered
  (Running + Ready, `app=kmesh` label) when `podName` is empty.
- **Kubernetes tools** use the Kubernetes API directly — no daemon needed.
- Large dumps are **summarized by default**; pass `filter` to drill down into
  full entries and `summary=false` for the raw dump. All output stays valid JSON.

## Tool groups at a glance

| Group | Tools |
| --- | --- |
| Cluster discovery | `get_version`, `list_daemon_pods`, `get_daemon_health`, `get_mesh_namespaces`, `list_mesh_services` |
| Status server (daemon) | `config_dump`, `get_bpf_maps`, `get_bpf_workload_details`, `get_bpf_ads_details`, `get_logger_levels` |
| Waypoints (Gateway API) | `list_waypoints`, `get_waypoint_status` |
| Security | `get_authz_status`, `get_ipsec_status` |
| Diagnostics | `diagnose_connectivity` |

---

## Cluster discovery

### `get_version`

- **What:** Kmesh daemon version and BPF operating mode (`kernel-native` / `dual-engine`).
- **Input:** `podName?`, `namespace?`
- **Data source:** daemon `GET /version` (status server :15200)

### `list_daemon_pods`

- **What:** All `kmesh-daemon` pods with node, status and IP.
- **Input:** `namespace?` (default `kmesh-system`)
- **Data source:** Kubernetes API — Pods with label `app=kmesh`

### `get_daemon_health`

- **What:** Readiness probe result of a daemon pod.
- **Input:** `podName?`, `namespace?`
- **Data source:** daemon `GET /debug/ready`

### `get_mesh_namespaces`

- **What:** Namespaces enrolled in the mesh (`istio.io/dataplane-mode=Kmesh`,
  matched case-insensitively like the daemon does).
- **Input:** none
- **Data source:** Kubernetes API — Namespaces by label

### `list_mesh_services`

- **What:** Kubernetes services in mesh-enrolled namespaces with cluster IP,
  ports and selectors.
- **Input:** `namespace?` (default: all mesh namespaces)
- **Data source:** Kubernetes API — Services (+ Namespaces for enrollment)

## Status server (daemon data)

### `config_dump`

- **What:** xDS dynamic listeners, clusters and routes (kernel-native) or the
  workload/service/policy cache (dual-engine). Mode auto-detected via `/version`.
- **Input:** `podName?`, `namespace?`, `mode?`, `summary?` (default true), `filter?`
- **Data source:** daemon `GET /debug/config_dump/{mode}`

### `get_bpf_maps`

- **What:** Kernel-level eBPF routing map state for the daemon's current mode.
- **Input:** `podName?`, `namespace?`, `mode?` (auto-detected), `summary?`, `filter?`
- **Data source:** daemon `GET /debug/config_dump/bpf/{mode}`

### `get_bpf_workload_details`

- **What:** Deep-dive into **dual-engine** BPF maps (frontends, backends,
  endpoints, services). Points you to `get_bpf_ads_details` if the daemon runs
  kernel-native.
- **Input:** `podName?`, `namespace?`, `summary?`, `filter?`
- **Data source:** daemon `GET /debug/config_dump/bpf/dual-engine`

### `get_bpf_ads_details`

- **What:** Deep-dive into **kernel-native (ADS)** BPF maps (clusters, listeners,
  routes). Points you to `get_bpf_workload_details` if the daemon runs dual-engine.
- **Input:** `podName?`, `namespace?`, `summary?`, `filter?`
- **Data source:** daemon `GET /debug/config_dump/bpf/kernel-native`

### `get_logger_levels`

- **What:** Log levels of Kmesh internal modules.
- **Input:** `podName?`, `namespace?`, `loggerName?`
- **Data source:** daemon `GET /debug/loggers[?name=X]`

## Waypoints (Gateway API)

### `list_waypoints`

- **What:** Waypoint proxies (Gateways with class `waypoint`) in a namespace or
  cluster-wide.
- **Input:** `namespace?` (default `default`), `allNamespaces?`
- **Data source:** Kubernetes API — Gateway API `Gateways`

### `get_waypoint_status`

- **What:** Health conditions of one waypoint (type/status/reason).
- **Input:** `name` (required), `namespace?`
- **Data source:** Kubernetes API — Gateway API `Gateways.Get`

## Security

### `get_authz_status`

- **What:** Whether authorization offload is enabled in the kernel.
- **Input:** `podName?`, `namespace?`
- **Data source:** daemon `GET /authz`

### `get_ipsec_status`

- **What:** Whether IPsec traffic encryption is configured — SPI, AEAD
  algorithm, key length and creation time. **Key material is never exposed.**
- **Input:** `namespace?` (default `kmesh-system`)
- **Data source:** Kubernetes API — Secret `kmesh-ipsec` (created by
  `kmeshctl secret create`)

## Diagnostics

### `diagnose_connectivity`

- **What:** Explains why traffic from `source` to `target` may fail. Resolves
  both sides against the workload cache, checks BPF wiring (backends), waypoint
  involvement and authorization policies, and returns a **verdict** with
  next-step hints.
- **Input:** `source` (required: pod/workload name or IP), `target` (required:
  service name, hostname, VIP or workload), `namespace?`, `podName?`
- **Data source (dual-engine):** daemon `GET /debug/config_dump/dual-engine`
  (workloads/services/policies) + `GET /debug/config_dump/bpf/dual-engine`
  (map state). In kernel-native mode it falls back to a shallow xDS match.
- **Verdicts:** `reachable-suspected`, `blocked-by-policy`, `missing-endpoints`,
  `source-not-enrolled`, `target-not-enrolled`, `target-not-found`,
  `needs-manual-inspection`

---

## Running the server

```bash
make mcp-server                          # builds out/kmeshctl
out/kmeshctl mcp serve                   # stdio transport (default)
out/kmeshctl mcp serve --transport sse   # HTTP + SSE on localhost:8080
```

### Claude Desktop

Add the server under `mcpServers` in `claude_desktop_config.json`
(Settings → Developer → Edit Config), then restart Claude Desktop:

```json
{
  "mcpServers": {
    "kmesh": {
      "command": "/path/to/kmeshctl",
      "args": ["mcp", "serve"]
    }
  }
}
```

### Cursor

Add the same entry to `~/.cursor/mcp.json` and restart Cursor.

### Make targets

| Target | Purpose |
| --- | --- |
| `make mcp-server` | build the kmeshctl binary used by the MCP server |
| `make mcp-test` | run the MCP unit tests |
| `make mcp-smoke` | run the end-to-end smoke test (needs a cluster with Kmesh) |

## Notes

- **Read-only.** No tool modifies the cluster or the daemon.
- **Error messages are actionable.** If the daemon does not answer, the error
  says so and includes the pod's phase/Ready status instead of a bare EOF.
- **Chaining works by design.** Tool descriptions point to their companions
  (e.g. `list_daemon_pods` → `get_daemon_health`, `list_waypoints` →
  `get_waypoint_status`, `diagnose_connectivity` hints name the exact follow-up
  tool and filter to use).
- **Secrets are safe.** `get_ipsec_status` reports only non-sensitive metadata;
  the AEAD key never leaves the secret.
