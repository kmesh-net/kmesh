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
      --cni-etc-path string    cni etc path (default "/etc/cni/net.d")
      --conflist-name string   cni conflist name
      --enable-mda             enable mda
  -h, --help                   help for kmesh-daemon
      --mode string            controller plane mode, valid values are [ads, workload] (default "ads")
      --plugin-cni-chained     kmesh cni plugins chained to anthor cni (default true)

# example
./kmesh-daemon --mode=ads
# example
./kmesh-daemon --mode=workload
# example
./kmesh-daemon --mode=ads --enable-mda
# example
./kmesh-daemon --mode=workload --enable-mda
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
