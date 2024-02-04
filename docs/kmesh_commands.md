# Commands Description

- kmesh-daemon

  ```sh
  # kmesh-daemon -h
  Usage of kmesh-daemon:
    -bpf-fs-path string
      	bpf fs path (default "/sys/fs/bpf")
    -cgroup2-path string
      	cgroup2 path (default "/mnt/kmesh_cgroup2")
    -enable-ads
      	[if -enable-kmesh] enable control-plane from ads (default true)
    -enable-kmesh
      	enable bpf kmesh
  
  # example
  ./kmesh-daemon -enable-kmesh
  # example
  ./kmesh-daemon -enable-kmesh -enable-ads=false
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

  - When `-enable-ads=true`, Kmesh automatically receives orchestration rules from the service grid control plane. In this configuration, do not run the `kmesh-cmd` command to deliver rules. Otherwise, configuration conflicts may occur.

  - The `path` specified by the `-bpf-fs-path` parameter must be the path of the bpf file system. For example:

    ```sh
    [root@localhost Kmesh]# mount | grep "/sys/fs/bpf"
    none on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
    ```
