# Kmesh命令说明

- kmesh-daemon

  ```sh
  # kmesh-daemon -h
  Usage of kmesh-daemon:
    -bpf-fs-path string
      	bpf fs path (default "/sys/fs/bpf")
    -cgroup2-path string
      	cgroup2 path (default "/mnt/kmesh_cgroup2")
    -config-file string
      	[if -enable-kmesh] deploy in kube cluster (default "/etc/kmesh/kmesh.json")
    -enable-ads
      	[if -enable-kmesh] enable control-plane from ads (default true)
    -enable-kmesh
      	enable bpf kmesh
    -service-cluster string
      	[if -enable-kmesh] TODO (default "TODO")
    -service-node string
      	[if -enable-kmesh] TODO (default "TODO")
  
  # example
  ./kmesh-daemon -enable-kmesh
  # example
  ./kmesh-daemon -enable-kmesh -enable-ads=true -config-file=envoy-rev0.json
  ./kmesh-daemon -enable-kmesh -enable-ads=false
  ```

- kmesh-cmd

  ```sh
  # kmesh-cmd -h
  Usage of kmesh-cmd:
    -config-file string
      	input config-resources to bpf maps (default "./config-resources.json")
  
  # example
  ./kmesh-cmd -config-file=examples/api-v2-config/config-resources.json
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

#### 
