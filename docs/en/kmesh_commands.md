# Commands Description

- kmesh-daemon

```sh
# kmesh-daemon -h
Start kmesh daemon

Usage:
  kmesh-daemon [flags]

Flags:
      --bpf-fs-path string     bpf fs path (default "/sys/fs/bpf")
      --cgroup2-path string    cgroup2 path (default "/mnt/kmesh_cgroup2")
      --enable-mda             enable mda
  -h, --help                   help for kmesh-daemon
      --mode string            controller plane mode, valid values are [kernel-native, dual-engine] (default "dual-engine")
      --monitoring string      enable kmesh traffic monitoring in daemon process(default "true")  
      --profiliing string      whether to enable profiling or not (default "false")
      --enable-ipsec string    enable ipsec encryption and authentication between nodes(default false)

# example
./kmesh-daemon --mode=kernel-native
# example
./kmesh-daemon --mode=dual-engine
# example
./kmesh-daemon --mode=kernel-native --enable-mda
# example
./kmesh-daemon --mode=dual-engine --enable-mda
```

- Admin Endpoints

  kmesh-daemon serves an admin interface on `localhost:15200` (implemented in `pkg/status/status_server.go`). It binds to the loopback interface only, so access it from inside the Kmesh daemon pod, or forward the port to your machine with `kubectl port-forward`. The recommended way to interact with these endpoints is through [`kmeshctl`](../ctl/kmeshctl.md), which wraps them.

  | Method | Path | Purpose |
  | --- | --- | --- |
  | GET | `/version` | Print kmesh-daemon version information |
  | GET | `/debug/ready` | Readiness probe, returns `OK` when the admin server is up |
  | GET | `/debug/loggers` | List logger scopes; with `?name=<scope>` print the level of one scope (the special scope `bpf` controls BPF program logging) |
  | POST | `/debug/loggers` | Set a logger level, request body `{"name": "<scope>", "level": "<level>"}` |
  | GET | `/debug/config_dump/kernel-native` | Dump the configuration cache in kernel-native mode |
  | GET | `/debug/config_dump/dual-engine` | Dump workloads, services and authorization policies in dual-engine mode |
  | GET | `/debug/config_dump/bpf/kernel-native` | Dump the BPF map configuration in kernel-native mode |
  | GET | `/debug/config_dump/bpf/dual-engine` | Dump the BPF map configuration in dual-engine mode |
  | POST | `/monitoring?enable=<bool>` | Enable or disable traffic monitoring (also toggles access log, workload metrics and connection metrics) |
  | POST | `/accesslog?enable=<bool>` | Enable or disable access log |
  | POST | `/workload_metrics?enable=<bool>` | Enable or disable workload metrics |
  | POST | `/connection_metrics?enable=<bool>` | Enable or disable connection metrics |
  | POST | `/authz?enable=<bool>` | Enable or disable XDP-based authorization offloading |
  | GET | `/debug/pprof/` | Go pprof profiling index (also `/debug/pprof/cmdline`, `/debug/pprof/profile`, `/debug/pprof/symbol`, `/debug/pprof/trace`) |

  ```sh
  # forward the admin port from a Kmesh daemon pod
  kubectl port-forward -n kmesh-system <kmesh-pod> 15200:15200

  # example: print version information
  curl http://localhost:15200/version

  # example: dump the configuration in dual-engine mode
  curl http://localhost:15200/debug/config_dump/dual-engine

  # example: set the default logger's level to debug
  curl -X POST http://localhost:15200/debug/loggers -d '{"name": "default", "level": "debug"}'
  ```

- Precautions

  - The `path` specified by the `-bpf-fs-path` parameter must be the path of the bpf file system. For example:

    ```sh
    [root@localhost Kmesh]# mount | grep "/sys/fs/bpf"
    none on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
    ```
