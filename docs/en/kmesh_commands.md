# Commands Description

- kmesh-daemon

```sh
# kmesh-daemon -h
Start kmesh daemon

Usage:
  kmesh-daemon [flags]

Flags:
      --bpf-fs-path string             bpf fs path (default "/sys/fs/bpf")
      --bpf-verifier-log-level uint32  bpf verifier log level bitmask for debugging bpf program loads (1=branch, 2=instruction, 4=stats; OR values together); 0 disables verifier logging (default 0)
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
# example
./kmesh-daemon --mode=dual-engine --bpf-verifier-log-level=1
```

- Commands Example

  ```sh
  # curl http://localhost:15200/help
   /help: print list of commands
   /options: print config options
   /bpf/kmesh/maps: print bpf kmesh maps in kernel
   /controller/envoy: print control-plane in envoy cache
   /controller/kubernetes: print control-plane in kubernetes cache
  
  # example
  curl http://localhost:15200/bpf/kmesh/maps
  curl http://localhost:15200/options
  ```

- Precautions

  - The `path` specified by the `-bpf-fs-path` parameter must be the path of the bpf file system. For example:

    ```sh
    [root@localhost Kmesh]# mount | grep "/sys/fs/bpf"
    none on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
    ```

  - `--bpf-verifier-log-level` is disabled (`0`) by default and adds no runtime overhead. Set it to debug bpf program load/verifier
    failures; the value is a bitmask passed straight through to the bpf verifier (`1`=branch, `2`=instruction, `4`=stats, values
    may be OR'd, e.g. `3`). When non-zero, kmesh captures the full verifier output and writes it to the daemon log.
