# Kmesh性能测试

## 基础测试组网

![perf_network](../../docs/pics/perf_network.png)

## 测试工具

Kmesh采用fortio、dstat做性能测试工具；fortio是一款功能强大的微服务负载测试库，可以统计tp90/tp99/qps等时延吞吐信息；dstat是一款系统信息统计工具，主要用它收集测试过程中CPU使用情况；

## 测试例说明

目录下包含了一组测试用例配置与脚本文件，用于在k8s集群环境下测试kmesh以及业界软件的各项性能；

### 环境准备

- 多节点k8s集群环境

- 安装istio

  - 下载并安装istio，参考[istio官方文档]( https://istio.io/latest/zh/docs/setup/getting-started/)

  ```sh
  curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.28.2 TARGET_ARCH=x86_64 sh -
  cd istio-1.28.2
  export PATH=$PWD/bin:$PATH
  istioctl install 
  ```

### 测试用例说明

共8项测试，每个子项目录中均包含有：

config和shell目录;

config：用于起fortio的pod的配置文件，和svc的配置文件

shell：自动化用例的测试脚本

#### big_small_test

该用例为多并发情况下性能测试，在同一个节点上起多个fortio的客户端或服务端，通过改变其中一个fortio所使用的资源(例如改变线程数，会引起cpu占用率和内存占用率变化)来观察对其他fortio打流测试的性能影响。

#### density_test

该用例为密度测试，即在同一个节点上部署多个fortio的客户端来对fortio集群进行负载测试，通过改变fortio-client的数量，收集系统资源使用情况（cpu和内存占用率）和负载测试的结果的统计信息(延时和qps信息)

本测试用例脚本中同时拉起多个fortio-client端，在每个client端内对svc端口进行打流测试，观察不同client内性能信息。

#### multiple

使用nginx多次转发(多跳)的情况下，系统资源使用情况和负载统计信息，并测试打流的延时和qps信息

#### qps_test

测试在不同qps下的系统资源使用情况(cpu和内存占用率)和负载统计信息

#### bookinfo_test

bookinfo作为后端情况下，测试不同线程情况下的系统资源使用情况和负载统计信息，并测试打流的延时和qps信息

#### long_test

测试在不同线程下的长连接的系统资源使用情况和负载统计信息，以及延时和qps信息

#### packsize_test

测试不同http包大小的情况下，系统资源使用情况和负载统计信息，以及延时和qps信息

#### short_test

测试短链接情况下，不同线程下系统资源使用情况和负载统计信息，以及延时和qps信息

### 使用示例

以长链接测试为例：

在部署完成k8s和istio的环境上进行测试:

- istio-envoy测试
- cilium测试
- kmesh测试

#### istio-envoy测试

开启istio-sidecar注入

`kubectl label namespace default istio-injection=enabled --overwrite`

拉起fortio-client和server以及service

`kubectl apply -f config/fortio-client.yaml`

`kubectl apply -f config/fortio-server.yaml`

`kubectl apply -f config/fortio-service.yaml`

执行脚本

`sh long_test.sh`

#### cilium测试

安装cilium (此模块测试不需要istio参与)

```bash
# https://github.com/cilium/cilium-cli/releases，下载cilium，解压安装

cilium install --helm-set-string kubeProxyReplacement=strict --helm-set-string extraConfig enable-envoy-config=true
```

拉起fortio-client和server以及service

`kubectl apply -f config/cilium_policy.yaml`

`kubectl apply -f config/fortio-client.yaml`

`kubectl apply -f config/fortio-server.yaml`

`kubectl apply -f config/fortio-service.yaml`

如果之前以及拉起了相关pod，则此时可以重启pod即可

`kubectl delete pod <fortio-xxx>`

删除之前的pod后deployment会重新拉起，

执行脚本

`sh long_test.sh`

#### kmesh测试

关闭istio-sidecar注入

`kubectl label namespace default istio-injection=unenabled --overwrite`

拉起fortio-client和server以及service

`kubectl apply -f config/fortio-client.yaml`

`kubectl apply -f config/fortio-server.yaml`

`kubectl apply -f config/fortio-service.yaml`

如果之前以及拉起了相关pod，则此时可以重启pod即可

`kubectl delete pod <fortio-xxx>`

删除之前的pod后deployment会重新拉起，

然后启动kmesh

执行脚本

`sh long_test.sh`

执行结果会在当前目录下根据时间新建文件夹，每个线程一个文件，查看执行结果，执行结果包括过程中的cpu和内存占用信息，以及fortio打流的延时和qps信息，可以对比kmesh与其他软件包的性能。
