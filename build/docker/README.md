## docker镜像说明

由于kmesh的部分能力对于内核版本有着较强的依赖，我们提供了两种kmesh的镜像：

一种是可直接在指定环境上使用的镜像，该镜像可提供kemsh的七层网络流量治理；

另一种是兼容模式的镜像，可根据当前宿主机的内核能力去选择编译kmesh的可用部分，该镜像不依赖于内核版本。

### 传统kmesh镜像

该镜像基于openeuler 23.03构建，可以在openeuler 2303的宿主机环境上快速部署七层网络流量治理能力

该镜像使用rpm构建方式构建kmesh的安装包并安装在镜像中，并提前准备了一份对应内核版本的kmesh.ko,在运行时插入宿主机内核，后通过start_kmesh.sh脚本启动kmesh

### 兼容模式镜像

兼容模式镜像在启动时会检查当前宿主机的内核环境，并依此判断kmesh可以在此环境上使能的能力进行编译运行

镜像中包含了kmesh编译所需要的大部分依赖，并保存了kmesh源码，在使用yaml文件运行kmesh的时候可以脱离宿主机环境的依赖软件包进行编译。通过将部分宿主机文件映射入镜像，判断所支持的kmesh能力进行选择编译。

#### 兼容模式镜像启动说明

镜像启动可以参考首页[快速启动](../../README-zh.md#快速开始)，容模式镜像启动步骤与其一致但是有若干注意事项：

- 需要保证宿主机环境上安装了kernel-headers和kernel-devel软件包以用于读取宿主机环境和编译内核模块(kmesh.ko)
- 启动的时候会在线编译，所有会花费较多时间并消耗较多内存，需要分配一定资源以保证启动成功

### 构建镜像

kmesh构建镜像是用于方便用户编译kmesh和构建出当前OS版本可用的kmesh镜像而发布，用户执行make docker命令的时候会使用本目录下的dockerfile，将编译输出件和运行依赖放入新的镜像中

#### dockerfile

使用该文件用于制作当前OS版本上可运行的kmesh镜像

基于oe2309 base镜像构建，将kmesh源码目录作为工作目录，

安装kmesh所有编译输出件，并放入运行依赖；

最后在运行时执行start_kmesh.sh脚本

#### kmesh.yaml

用户可直接使用此文件在环境上以daemonset模式启动kmesh

该文件设置了一些映射目录和kmesh镜像运行所需资源，其中为在线编译的镜像新增了一些可选项(仅在线编译使用)

| 类别      | 名称                         | 说明                                                         | 配置样例                                                     | 备注                                               |
| --------- | ---------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------- |
| volume    | mnt                          | kmesh启动过程中需要mount部分cgroup目录                       | - name: mnt<br/>           hostPath:<br/>             path: /mnt |                                                    |
| volume    | sys-fs-bpf                   | 将ebpf程序挂载于宿主机上，需要宿主机的ebpf目录               | - name: sys-fs-bpf<br/>           hostPath:<br/>             path: /sys/fs/bpf |                                                    |
| volume    | lib-modules                  | 编译kmesh.ko需要该目录                                       | - name: lib-modules<br/>           hostPath:<br/>             path: /lib/modules |                                                    |
| volume    | cni                          | 读取k8s集群的cni配置文件                                     | - name: cni <br/>           hostPath:<br/>             path: /etc/cni/net.d |                                                    |
| volume    | kmesh-cni-install-path | 写入kmesh的cni文件到k8s集群                            | - name: kmesh-cni-install-path<br/>           hostPath:<br/>             path: /opt/cni/bin |                                                    |
| volume    | linux-bpf                    | 将宿主机环境上的kernel-headers包的/usr/include/linux/bpf.h文件映射到镜像内，通过该文件来判断当前宿主机所支持的helper函数和是否对内核进行过增强，进而判断支持kmesh的哪些能力，去对编译宏开关进行编辑并进行编译 | - name: linux-bpf<br/>           hostPath:<br/>             path: /usr/include/linux/bpf.h | 可选项，兼容模式镜像需要使用                       |
| volume    | ko-build-path                | kmesh的七层治理能力需要对内核进行增强并插入kmesh.ko文件，内核模块的编译环境需要和宿主机环境保持一致，所以需要将宿主机上的/lib/module/build目录映射到镜像中，大多数环境中该目录都是软链接到/usr/src/$(uname -r) 目录，所以需要将/usr/src目录映射至镜像中 | - name: ko-build-path<br/>           hostPath:<br/>             path: /usr/src | 可选项，兼容模式镜像需要使用                       |
| args      |                              | 镜像启动时的执行动作，可自定义修改                           | ["./start_kmesh.sh -mode=ads"]          | 默认使用ads控制面                                  |
| env       | XDS_ADDRESS              | 指定使用的网络控制平面服务                                   | - name: XDS_ADDRESS<br/>  value: istio-system:istiod     | 可以根据当前集群环境                               |
| resources | memory                       | 镜像所需要的内存空间大小                                     | memory: "800Mi"                                              | 兼容模式镜像建议800Mi以上                          |

#### start_kmesh.sh

镜像启动脚本，用于在镜像容器创建时调度所需资源，执行所需步骤：

- 加载kmesh.ko并将kmesh_cgroup2挂载到cgroup2
- kmesh-daemon按照指定参数启动

### 常见问题

1、各种重复定义或者缺少某些定义导致的编译失败或者其他编译失败：

​  多数时候是由于宿主机上没有安装kernel-headers，导致部分头文件文件读取失败，无法正确识别宿主机环境，容易导致编译失败

2、kmesh.ko编译失败：

​  宿主机上没有安装kerne-devel软件包，导致缺少编译ko的依赖

3、镜像启动时找不到/root/.kube/config 文件，启动失败：

​  由于不同的K8S环境的创建方式不同，config位置也不同，用户需要在kmesh启动的时候去指定kmesh.yaml文件中的kube-config-path的hostpath，将其映射到镜像中的指定位置

4、镜像启动时进程资源不足被杀死

​  主要是由于yaml文件中指定资源过小导致，建议使用代码仓中提供的yaml文件(指定了800Mi内存)

5、镜像启动时有curl报错，可以忽略，该报错不会影响后续执行。

​  由于编译脚本中存在部分yum install动作会去检查远端repo源，我们的镜像中已经包含了所有编译依赖，无需再install，后续会优化逻辑步骤与日志信息。
