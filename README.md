# Kmesh

#### 介绍
Kmesh (kernel mesh) is a data plane software for service grids. It is dedicated to providing infrastructure for service communication and service governance for cloud applications, provides better latency and noise floor performance.

#### 软件架构
软件架构说明


#### 安装教程

1.  xxxx
2.  xxxx
3.  xxxx

#### 使用说明

1.  xxxx
2.  xxxx
3.  xxxx

#### 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request


#### 特技

1.  使用 Readme\_XXX.md 来支持不同的语言，例如 Readme\_en.md, Readme\_zh.md
2.  Gitee 官方博客 [blog.gitee.com](https://blog.gitee.com)
3.  你可以 [https://gitee.com/explore](https://gitee.com/explore) 这个地址来了解 Gitee 上的优秀开源项目
4.  [GVP](https://gitee.com/gvp) 全称是 Gitee 最有价值开源项目，是综合评定出的优秀开源项目
5.  Gitee 官方提供的使用手册 [https://gitee.com/help](https://gitee.com/help)
6.  Gitee 封面人物是一档用来展示 Gitee 会员风采的栏目 [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)

## Usage Tutorial

build

```sh
make clean
make
make install
```

config

```sh
mkdir /mnt/cgroup2
mount -t cgroup2 none /mnt/cgroup2/

kubectl exec xxx-pod-name -c istio-proxy -- cat etc/istio/proxy/envoy-rev0.json > envoy-rev0.json
---
       , {
        "name": "xds-grpc",
        "type" : "STATIC",
        "connect_timeout": "1s",
        "lb_policy": "ROUND_ROBIN",
        "load_assignment": {
          "cluster_name": "xds-grpc",
          "endpoints": [{
            "lb_endpoints": [{
              "endpoint": {
                "address":{
                  "socket_address": {
                    "protocol": "TCP",
                    "address": "192.168.123.249", # istiod pod IP
                    "port_value": 15010
                  }
                }
              }
            }]
          }]
        },
---
```

kmesh-daemon

```sh
# kmesh-daemon -h
Usage of kmesh-daemon:
  -bpf-fs-path string
    	bpf fs path (default "/sys/fs/bpf")
  -cgroup2-path string
    	cgroup2 path (default "/mnt/cgroup2")
  -config-file string
    	[if -enable-kmesh] deploy in kube cluster (default "/etc/istio/proxy/envoy-rev0.json")
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

kmesh-cmd

```sh
# kmesh-cmd -h
Usage of kmesh-cmd:
  -config-file string
    	input config-resources to bpf maps (default "./config-resources.json")

# example
./kmesh-cmd -config-file=examples/api-v2-config/config-resources.json
```

admin

```sh
# curl http://localhost:15200/help
	/help: print list of commands
	/options: print config options
	/bpf/kmesh/maps: print bpf kmesh maps in kernel
	/controller/envoy: print control-plane in envoy cache
	/controller/kubernetes: print control-plane in kubernetes cache

# example
curl http://localhost:15200/bpf/kmesh/maps
curl http://localhost:15200/controller/envoy
```
