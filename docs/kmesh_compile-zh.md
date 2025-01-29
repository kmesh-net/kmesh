# Kmesh编译构建

Kmesh需要在拥有Kmesh内核增强特性的Linux环境中编译构建。当前可以在多个操作系统中编译和运行Kmesh，具体操作系统版本可以参见[Kmesh支持系统](kmesh_support-zh.md)。

## 编译构建

### 准备工作

- docker-engine安装

  ```sh
  [root@dev Kmesh]# yum install docker-engine
  ```

- 镜像原料准备

  Kmesh的镜像编译需要准备好kmesh源码，以及kmesh-build镜像，镜像可以通过如下命令获取

  注意：kmesh-build镜像需要和源码版本相匹配
  
  ```bash
  docker pull ghcr.io/kmesh-net/kmesh-build:latest
  ```

### 源码编译

- 代码下载

  ```sh
  [root@dev tmp]# git clone https://github.com/kmesh-net/kmesh.git
  ```

- 代码修改编译

  ```sh
  [root@dev tmp]# cd kmesh/
  [root@dev Kmesh]# make build
  ```

  kmesh会在编译镜像中进行编译构建，并将编译产物输出至out目录

  ```bash
  [root@localhost kmesh]# ls out/amd64/
  kmesh-daemon       libbpf.so    libbpf.so.0.8.1       libkmesh_deserial.so  libprotobuf-c.so.1      mdacore
  kmesh-cni  kmeshctl  libboundscheck.so  libbpf.so.0  libkmesh_api_v2_c.so  libprotobuf-c.so      libprotobuf-c.so.1.0.0
  ```

### docker image编译

- 镜像制作

  在kmesh源码目录下执行`make docker`

  可以由用户指定参数构建，示例如下：

  ```bash
  #用户自定义HUB TARGET TAG内容，若未指定则采用默认值：
  HUB=ghcr.io/kmesh-net
  TARGET=kmesh
  TAG= #git sha
  
  [root@localhost kmesh]# make docker
  ...
  Successfully tagged ghcr.io/kmesh-net/kmesh:b68790eb07830e757f4ce6d1c478d0046ee79730
  
  [root@localhost kmesh]# make docker HUB=ghcr.io/kmesh-net TARGET=kmesh TAG=latest
  ...
  Successfully tagged ghcr.io/kmesh-net/kmesh:latest
  ```
  
  查看本地镜像仓库已有Kmesh镜像
  
  ```sh
  [root@dev docker]# docker images
  REPOSITORY                          TAG                                        IMAGE ID            CREATED             SIZE
  ghcr.io/kmesh-net/kmesh             v0.2.0                                     71aec5898c44        10 days ago         457MB
  ```
  
### Kmesh编译清理

  ```sh
  [root@dev Kmesh]# make clean
  ```

