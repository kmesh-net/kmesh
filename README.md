# Kmesh

### 介绍
Kmesh是一种基于可编程内核实现的高性能网格数据面；提供serviceMesh场景下高性能的服务通信能力。

### 软件架构

![kmesh-arch](docs/pics/kmesh-arch.png)

Kmesh的主要部件包括：

- kmesh-controller：

  kmesh管理程序，负责Kmesh生命周期管理、XDS协议对接、观测运维等功能；

- kmesh-api：

  kmesh对外提供的api接口层，主要包括：xds转换后的编排API、观测运维通道等；

- kmesh-runtime：

  kernel中实现的支持L3~L7流量编排的运行时；

- kmesh-orchestration：

  基于ebpf实现L3~L7流量编排，如路由、灰度、负载均衡等；

- kmesh-probe：

  观测运维探针，提供端到端观测能力；


### 快速开始

#### 准备工作

Kmesh正常运行依赖对kernel的增强特性修改，这些增强特性正在向上游社区推送；在此之前，提供了两种方式获取包含Kmesh增强特性的kernel包：

- 针对主流kernel版本归档包含Kmesh增强特性的发布包

  | 基线版本                                                     | Kmesh特性增强版本                              | 备注 |
  | ------------------------------------------------------------ | ---------------------------------------------- | ---- |
  | [openEuler_2203_LTS_x86](https://repo.openeuler.org/openEuler-22.03-LTS/everything/x86_64/Packages/kernel-5.10.0-60.18.0.50.oe2203.x86_64.rpm) | [kmesh_openEuler_2203_LTS_x86](release/kernel) |      |
  | centos                                                       | TODO                                           |      |
  | Ubuntu                                                       | TODO                                           |      |

- 基于Kmesh增强特性patch制作kernel包

  [基于Kmesh增强特性构建kernel包](docs/kmesh_kernel_compile.md)

编译运行Kmesh前，需要安装包含Kmesh增强特性的kernel包重启；

```sh
[root@dev kernel]# ll
total 67M
-rw-r--r--. 1 root root  51M Nov  2 21:59 kernel-5.10.0-60.18.0.99.x86_64.rpm
-rw-r--r--. 1 root root  15M Nov  2 21:59 kernel-devel-5.10.0-60.18.0.99.x86_64.rpm
-rw-r--r--. 1 root root 2.2M Nov  2 21:59 kernel-headers-5.10.0-60.18.0.99.x86_64.rpm
# 编译/运行环境安装
[root@dev kernel]# rpm -Uvh kernel-5.10.0-60.18.0.99.x86_64.rpm
# 编译环境需额外安装kernel-headers/kernel-devel
[root@dev kernel]# rpm -Uvh kernel-headers-5.10.0-60.18.0.99.x86_64.rpm
[root@dev kernel]# rpm -Uvh kernel-devel-5.10.0-60.18.0.99.x86_64.rpm
```

详细的开发编译流程，可参考[Kmesh编译构建](docs/kmesh_compile.md)；

#### Kmesh集群启动模式

在serviceMesh环境中启动Kmesh当前支持rpm、容器两种模式；

- 基于rpm启动部署

  1. 下载一个[Kmesh发行包](release/Kmesh/rpm)安装：

     ```sh
     [root@dev ~]# rpm -Uvh kmesh.rpm
     ```

  2. Kmesh启动配置修改，设置集群中控制面程序ip信息（如istiod ip地址）；

     ```sh
     [root@dev ~]# vim /etc/kmesh/kmesh.json
     {
             "name": "xds-grpc",		# 1 找到该项配置
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
                         "address": "192.168.123.123", # 2 设置控制面ip(如istiod ip)
                         "port_value": 15010
                       }
                     }
                   }
                 }]
               }]
             },
     ```

  3. 启动Kmesh

     ```sh
     # 启动Kmesh服务
     [root@dev ~]# systemctl start kmesh.service
     
     # 查看kmesh运行状态
     [root@dev ~]# systemctl status kmesh.service
     ```

  4. 停止Kmesh

     ```sh
     [root@dev ~]# systemctl stop kmesh.service
     ```
     
  5. 卸载Kmesh rpm

     ```sh
     [root@dev ~]# rpm -evh kmesh
     ```

- 基于容器镜像启动部署

  - 从代码仓中获取[容器镜像](release/Kmesh/docker)并加载到集群
  
    ```sh
    [root@dev Kmesh]# docker load -i kmesh-1.0.1.tar
    ```
    
  - 启动Kmesh
  
    - 启动Kmesh容器
  
      ```sh
      [root@dev Kmesh]# docker run -itd --privileged=true -v /mnt:/mnt -v /sys/fs/bpf:/sys/fs/bpf -v /lib/modules:/lib/modules --name kmesh kmesh:1.0.1
      ```
  
    - daemonset方式启动Kmesh
  
      ```sh
      [root@dev Kmesh]# kubectl apply -f kmesh.yaml
      ```

#### Kmesh本地启动模式

为了方便快速验证，Kmesh支持本地启动模式，本地启动模式下，无需部署k8s/istio，可在单节点上直接启动；

- 替换包含Kmesh增强特性的内核包

  具体步骤参考[准备工作](#准备工作)；

- 下载Kmesh.rpm安装

  ```sh
  [root@dev ~]# rpm -Uvh kmesh.rpm
  ```

- 修改kmesh.service，禁用ads开关

  ```sh
  [root@dev ~]# vim /usr/lib/systemd/system/kmesh.service
  ExecStart=/usr/bin/kmesh-daemon -enable-kmesh -enable-ads=false
  [root@dev ~]# systemctl daemon-reload
  
  # service启动
  [root@dev ~]# systemctl start kmesh.service
  ```

#### demo部署演示

以istio的bookinfo示例服务为例，演示部署Kmesh后进行百分比灰度访问的执行过程；

- 启动Kmesh

  ```sh
  [root@vm-x86-11222]# systemctl start kmesh.service
  ```

- bookinfo环境准备

  部署istio及启动bookinfo的流程可参考[bookinfo环境部署](https://istio.io/latest/docs/setup/getting-started/)；需要注意的是，无需为namespace注入`istio-injection` 标记，即不需要启动istio的数据面代理程序；

  因此准备好的环境上关注如下信息：

  ```sh
  # default ns未设置istio的sidecar注入
  [root@vm-x86-11222 networking]# kubectl get namespaces --show-labels
  NAME              STATUS   AGE   LABELS
  default           Active   92d   <none>
  ```

- 访问bookinfo

  ```sh
  [root@vm-x86-11222 networking]# productpage_addr=`kubectl get svc -owide | grep productpage | awk {'print $3'}`
  [root@vm-x86-11222 networking]# curl http://$productpage_addr:9080/productpage
  ```

- demo演示

  demo演示了基于Kmesh，对bookinfo的reviews服务实施百分比路由规则，并成功访问；

  ![demo_bookinfo_v1_v2_8_2](docs/pics/demo_bookinfo_v1_v2_8_2.svg)

### Kmesh性能

基于fortio对比测试了Kmesh和envoy的数据面执行性能；测试结果如下：

![fortio_performance_test](docs/pics/fortio_performance_test.png)

详细的测试步骤请参考[Kmesh性能测试](test/performance/README.md)；

### 特性说明

#### Kmesh开发指南

[Kmesh开发指南](docs/kmesh_development_guide.md)

#### Kmesh命令列表

[Kmesh命令列表](docs/kmesh_commands.md)

#### 测试框架

[Kmesh测试框架](./test/README.md)

### Kmesh能力地图

| 特性域       | 特性                  |            2022            |          2023.H1           |          2023.H2           |          2024.H1           |          2024.H2           |
| ------------ | --------------------- | :------------------------: | :------------------------: | :------------------------: | :------------------------: | :------------------------: |
| 流量管理     | sidecarless网格数据面 | ![](docs/pics/support.png) |                            |                            |                            |                            |
|              | 基于ebpf的可编程治理  | ![](docs/pics/support.png) |                            |                            |                            |                            |
|              | http1.1协议           | ![](docs/pics/support.png) |                            |                            |                            |                            |
|              | http2协议             |                            | ![](docs/pics/support.png) |                            |                            |                            |
|              | grpc协议              |                            |                            | ![](docs/pics/support.png) |                            |                            |
|              | quic协议              |                            |                            | ![](docs/pics/support.png) |                            |                            |
|              | 重试                  |                            | ![](docs/pics/support.png) |                            |                            |                            |
|              | 路由                  | ![](docs/pics/support.png) |                            |                            |                            |                            |
|              | 负载均衡              | ![](docs/pics/support.png) |                            |                            |                            |                            |
|              | 故障注入              |                            |                            | ![](docs/pics/support.png) |                            |                            |
|              | 灰度发布              | ![](docs/pics/support.png) |                            |                            |                            |                            |
| 服务安全     | 基于SSL的双向认证     |                            | ![](docs/pics/support.png) |                            |                            |                            |
|              | L7授权                |                            |                            | ![](docs/pics/support.png) |                            |                            |
|              | 治理pod级隔离         |                            |                            | ![](docs/pics/support.png) |                            |                            |
| 流量监控     | 治理指标监控          |                            | ![](docs/pics/support.png) |                            |                            |                            |
|              | E2E可观测             |                            |                            |                            |                            | ![](docs/pics/support.png) |
| 软硬件协同   | XPU卸载               |                            |                            |                            | ![](docs/pics/support.png) |                            |
| 可扩展       | 应用协议自定义扩展    |                            |                            | ![](docs/pics/support.png) |                            |                            |
|              | 插件式扩展能力        |                            |                            |                            | ![](docs/pics/support.png) |                            |
| 运行环境支持 | 容器                  | ![](docs/pics/support.png) |                            |                            |                            |                            |
|              | 虚机                  |                            |                            | ![](docs/pics/support.png) |                            |                            |
|              | 裸机                  |                            |                            | ![](docs/pics/support.png) |                            |                            |
|              | 多集群                |                            |                            |                            |                            | ![](docs/pics/support.png) |
|              | serverless            |                            |                            |                            |                            | ![](docs/pics/support.png) |
| 部署形态     | per-node形态          | ![](docs/pics/support.png) |                            |                            |                            |                            |
|              | gateway形态           |                            |                            |                            |                            | ![](docs/pics/support.png) |

### 演进路标

TODO
