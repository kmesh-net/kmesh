# Kmesh编译构建

## 准备工作

Kmesh软件包需要在拥有Kmesh内核增强特性的linux环境上编译构建，参考[准备工作](../README.md#准备工作)；

## 编译构建

### 源码编译

- 代码下载

  ```sh
  [root@dev tmp]# git clone https://github.com/kmesh-net/kmesh.git
  ```

- 代码修改编译

  ```sh
  [root@dev tmp]# cd Kmesh/
  [root@dev Kmesh]# ./build.sh -b
  ```

- Kmesh程序安装

  ```sh
  # 安装脚本显示了Kmesh所有安装文件的位置
  [root@dev Kmesh]# ./build.sh -i
  ```

- Kmesh编译清理

  ```sh
  [root@dev Kmesh]# ./build.sh -c
  ```

- Kmesh程序卸载

  ```sh
  [root@dev Kmesh]# ./build.sh -u
  ```

### RPM编译安装

- 准备工作

  安装rpm编译工具

  ```sh
  [root@dev tmp]# yum install -y rpm-build rpmdevtools
  ```

- 代码下载

  ```sh
  [root@dev tmp]# git clone https://github.com/kmesh-net/kmesh.git
  ```

- 创建build环境

  ```sh
  # 生成/root/rpmbuild编译环境
  [root@dev Kmesh]# rpmdev-setuptree
  ```

- 代码压缩包、spec放入build环境

  ```sh
  # 代码压缩包放入/root/rpmbuild/SOURCE
  # 注意压缩包的名称是kmesh-{version}.tar.gz，{version}参考kmesh.spec中的Version字段
  [root@dev tmp]# mv Kmesh kmesh-1.0.0
  [root@dev tmp]# tar zcvf /root/rpmbuild/SOURCES/kmesh-1.0.0.tar.gz kmesh-1.0.0/
  
  # kmesh.spec放入/root/rpmbuild/SPEC
  [root@dev kmesh-1.0.0]# cp kmesh.spec /root/rpmbuild/SPECS/
  ```

- rpm编译

  ```sh
  [root@dev tmp]# cd /root/rpmbuild/SPECS/
  [root@dev SPECS]# rpmbuild -bb kmesh.spec
  
  # 编译结果在/root/rpmbuild/RPM/{arch}目录下
  [root@dev tmp]# cd /root/rpmbuild/RPMS/x86_64/
  [root@dev x86_64]# ll
  total 9.2M
  -rw-r--r--. 1 root root 9.2M Nov  5 11:11 kmesh-1.0.0-1.x86_64.rpm
  [root@dev x86_64]#
  ```

### docker image编译

- 准备工作

  - docker-engine安装

    ```sh
    [root@dev Kmesh]# yum install docker-engine
    ```

  - 镜像原料准备

    Kmesh的镜像编译需要准备好Kmesh.rpm、kmesh.dockerfile、start_kmesh.sh启动脚本；将其放在一个目录下；

    kmesh.dockerfile、start_kmesh.sh归档在代码仓目录下：

    ```sh
    [root@dev Kmesh]# ll build/docker/
    total 12K
    -rw-r--r--. 1 root root  793 Nov 25 01:31 kmesh.dockerfile
    -rw-r--r--. 1 root root 1.5K Nov 25 10:48 kmesh.yaml
    -rw-r--r--. 1 root root  764 Nov 25 01:31 start_kmesh.sh
    ```

    将镜像原料放到一个目录下

    ```sh
    [root@dev docker]# ll
    total 9.2M
    -rw-r--r--. 1 root root 9.2M Nov 25 06:37 kmesh-0.0.1.x86_64.rpm
    -rw-r--r--. 1 root root  793 Nov 25 01:36 kmesh.dockerfile
    -rw-r--r--. 1 root root  764 Nov 25 01:36 start_kmesh.sh
    ```

- 镜像制作

  ```sh
  [root@dev docker]# docker build -f kmesh.dockerfile -t kmesh-0.0.1 .
  ```

  查看本地镜像仓库已有Kmesh镜像

  ```sh
  [root@dev docker]# docker images
  REPOSITORY            TAG                 IMAGE ID            CREATED             SIZE
  kmesh-0.0.1           latest              e321b18d5fee        4 hours ago         675MB
  ```

## Kmesh发布件说明

### rpm包说明

rpm安装后可以看到Kmesh的发布件内容，包含：Kmesh配置文件、Kmesh内核模块、Kmesh动态库、Kmesh用户态程序、service相关文件；

```sh
[root@dev tmp]# rpm -ql kmesh
/etc/kmesh
/etc/kmesh/kmesh.json
/lib/modules/kmesh
/lib/modules/kmesh/kmesh.ko
/usr/bin/kmesh-cmd
/usr/bin/kmesh-daemon
/usr/bin/kmesh-start-pre.sh
/usr/bin/kmesh-stop-post.sh
/usr/lib/systemd/system/kmesh.service
/usr/lib64/libkmesh_api_v2_c.so
/usr/lib64/libkmesh_deserial.so
[root@dev tmp]#
```

- Kmesh配置文件

  - Kmesh配置文件目录

    ```sh
    /etc/kmesh
    ```

  - Kmesh启动配置文件

    ```sh
    /etc/kmesh/kmesh.json
    ```

    配置Kmesh启动需要的全局配置信息 ，包括：serviceMesh控制面程序ip/port配置等；用户根据实际环境配置；

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

  - Kmesh内核模块

    ```sh
    /lib/modules/kmesh
    /lib/modules/kmesh/kmesh.ko
    ```

  - Kmesh动态库

    ```
    # Kmesh治理模型proto编译出的c的读写访问动态库
    /usr/lib64/libkmesh_api_v2_c.so
    # 将治理模型配置转换成内核数据格式的数据转换库
    /usr/lib64/libkmesh_deserial.so
    ```

  - Kmesh用户态程序

    ```sh
    # Kmesh主程序，完成ebpf程序管理、serviceMesh控制面对接等工作
    /usr/bin/kmesh-daemon
    # 本地启动模式下，可通过kmesh-cmd注入流量治理规则
    /usr/bin/kmesh-cmd
    ```

  - service相关文件

    Kmesh支持service启动，定义了service启动相关的配置文件

    ```sh
    /usr/bin/kmesh-start-pre.sh
    /usr/bin/kmesh-stop-post.sh
    /usr/lib/systemd/system/kmesh.service
    ```

### 镜像文件说明

代码仓中归档了镜像相关发布件

```sh
[root@dev Kmesh]# tree release/Kmesh/docker/
release/Kmesh/docker/
├── kmesh-1.0.1.tar			# Kmesh镜像包
└── kmesh.yaml				# Daemonset配置文件
```

- kmesh.yaml

  kmesh.yaml是kmesh的daemonset部署样例， 其中需要重点关注的是网格控制面的service信息设置，实际部署时根据集群信息刷新；

  ```yaml
  env:
             - name: MESH_CONTROLLER
             	 # 格式:"{namespace}:{servicename}"
               value:istio-system:istiod
  ```

