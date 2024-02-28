# Kmesh命令说明

- kmesh-daemon

  ```sh
  # kmesh-daemon -h
  Usage of kmesh-daemon:
    -bpf-fs-path string
      	bpf fs path (default "/sys/fs/bpf")
    -cgroup2-path string
      	cgroup2 path (default "/mnt/kmesh_cgroup2")
    -mode
        controller plane mode, ads/workload optional (default "ads")
    -enable-mda
        enable mda
  
  # example
  ./kmesh-daemon -mode=ads
  # example
  ./kmesh-daemon -mode=workload
  # example
  ./kmesh-daemon -mode=ads -enable-mda
  # example
  ./kmesh-daemon -mode=workload -enable-mda
  ```

- 运维相关

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

- 命令使用注意事项

  - `-bpf-fs-path`参数指定的`path`要求是bpf文件系统路径；如：

    ```sh
    [root@localhost Kmesh]# mount | grep "/sys/fs/bpf"
    none on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
    ```
