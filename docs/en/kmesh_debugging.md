# Debugging Kmesh

This guide describes how to inspect and debug a running Kmesh daemon — how to
turn on debug logs, view the configuration dump, and use the other built-in
debug interfaces — without having to read the Kmesh source code.

## The Kmesh admin interface

Each `kmesh-daemon` process exposes a local admin/debug HTTP server on
`localhost:15200`. Because it is bound to the loopback address inside the pod,
you reach it in one of two ways:

- **`kmeshctl`** (recommended) — the command line tool wraps these endpoints for
  you, so you do not need to exec into the pod.
- **`kubectl exec` + `curl`** — for the raw HTTP endpoints, run `curl` from
  inside the Kmesh pod.

Kmesh runs as a DaemonSet. Find the daemon pod on the node you want to debug:

```sh
kubectl get pods -n kmesh-system -o wide
```

> In the examples below, replace `<kmesh-daemon-pod>` with the name of that pod
> and adjust the namespace (`kmesh-system` by default) to match your install.

## Daemon logs

The most direct way to see what the daemon is doing is its standard output:

```sh
kubectl logs -n kmesh-system <kmesh-daemon-pod>

# follow the logs:
kubectl logs -n kmesh-system <kmesh-daemon-pod> -f
```

## Adjusting log levels

Kmesh groups its logs into named loggers, each with its own level. You can read
and change them at runtime — no restart required.

List the available loggers:

```sh
kmeshctl log <kmesh-daemon-pod>
```

Get the level of a single logger:

```sh
kmeshctl log <kmesh-daemon-pod> default
```

Set a logger's level (for example, raise the `default` logger to `debug`):

```sh
kmeshctl log <kmesh-daemon-pod> --set default:debug
```

To increase the verbosity of the **eBPF program logs**, set the `bpf` logger,
which accepts `error`, `warn`, `info`, and `debug`:

```sh
kmeshctl log <kmesh-daemon-pod> --set bpf:debug
```

eBPF log output is surfaced in the daemon log, so view it with `kubectl logs`
as shown above.

The same operations are available over HTTP at `/debug/loggers` (`GET` to read,
`POST` to set).

## Viewing the configuration dump

The config dump shows the xDS configuration Kmesh has received from the control
plane (workloads, services, authorization policies, clusters, listeners, etc.).
Use the mode your daemon is running in — `dual-engine` or `kernel-native`:

```sh
# Dual-Engine mode (table output):
kmeshctl dump <kmesh-daemon-pod> dual-engine

# Kernel-Native mode (table output):
kmeshctl dump <kmesh-daemon-pod> kernel-native

# Raw JSON:
kmeshctl dump <kmesh-daemon-pod> dual-engine -o json
```

The equivalent HTTP endpoints are:

- `/debug/config_dump/dual-engine` — workloads, services and policies (dual-engine mode)
- `/debug/config_dump/kernel-native` — clusters, listeners and routes (kernel-native mode)
- `/debug/config_dump/bpf/dual-engine` and `/debug/config_dump/bpf/kernel-native` —
  the contents of the underlying eBPF maps, useful for confirming that config has
  actually been written into the kernel

For example, from inside the pod:

```sh
curl -s http://localhost:15200/debug/config_dump/dual-engine
```

## Access logs and metrics

Kmesh can emit per-connection access logs and traffic metrics, which are helpful
for debugging connectivity and traffic flow. These require monitoring to be
enabled.

Access logs and metrics are controlled with `kmeshctl monitoring`:

```sh
# Access logs, service and workload metrics together:
kmeshctl monitoring <kmesh-daemon-pod> --all enable

# Access logs only:
kmeshctl monitoring <kmesh-daemon-pod> --accesslog enable

# Workload-granularity metrics:
kmeshctl monitoring <kmesh-daemon-pod> --workloadMetrics enable

# Connection-granularity metrics:
kmeshctl monitoring <kmesh-daemon-pod> --connectionMetrics enable
```

Use `disable` in place of `enable` to turn each off.

## Debugging authorization

When traffic is being unexpectedly allowed or denied, inspect and toggle the
XDP authorization (authz) offload program:

```sh
# Show the current authz status:
kmeshctl authz status <kmesh-daemon-pod>

# Enable / disable authz offloading:
kmeshctl authz enable <kmesh-daemon-pod>
kmeshctl authz disable <kmesh-daemon-pod>
```

The authorization policies themselves are visible in the `dual-engine` config
dump described above.

## Version information

When reporting a bug, include the build version:

```sh
kmeshctl version <kmesh-daemon-pod>
```

This is also available at the `/version` HTTP endpoint.

## Readiness

The daemon exposes a readiness endpoint at `/debug/ready`:

```sh
curl -s http://localhost:15200/debug/ready
```

## Profiling (pprof)

For performance debugging, the daemon serves Go `pprof` data under
`/debug/pprof/`. Collect a profile from inside the pod, for example a 30-second
CPU profile:

```sh
curl -s http://localhost:15200/debug/pprof/profile?seconds=30 -o cpu.pprof
```

Then analyze it with `go tool pprof cpu.pprof`.

## Quick reference

| Task | Command | HTTP endpoint (`localhost:15200`) |
| --- | --- | --- |
| Daemon logs | `kubectl logs -n kmesh-system <kmesh-daemon-pod>` | — |
| List / set log level | `kmeshctl log <kmesh-daemon-pod> [--set <logger>:<level>]` | `/debug/loggers` |
| Config dump | `kmeshctl dump <kmesh-daemon-pod> <mode>` | `/debug/config_dump/{dual-engine,kernel-native}` |
| eBPF map dump | — | `/debug/config_dump/bpf/{dual-engine,kernel-native}` |
| Access logs | `kmeshctl monitoring [<kmesh-daemon-pod>] --accesslog enable/disable` | `/accesslog` |
| Monitoring / metrics | `kmeshctl monitoring [<kmesh-daemon-pod>] <flags>` | `/monitoring`, `/workload_metrics`, `/connection_metrics` |
| Authorization | `kmeshctl authz enable/disable/status [<kmesh-daemon-pod>]` | `/authz` |
| Version | `kmeshctl version [<kmesh-daemon-pod>]` | `/version` |
| Readiness | — | `/debug/ready` |
| Profiling | — | `/debug/pprof/` |

## See also

- [kmeshctl command reference](../ctl/kmeshctl.md)
- [Deploy and develop Kmesh in kind](kmesh_deploy_and_develop_in_kind.md)
- [Kmesh commands](kmesh_commands.md)
