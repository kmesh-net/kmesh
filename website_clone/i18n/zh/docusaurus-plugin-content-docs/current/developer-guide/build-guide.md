---
sidebar_position: 1
title: 如何构建
---

Kmesh 需要在具有 Kmesh 内核增强功能的 Linux 环境中编译和构建。目前，Kmesh 可以在多个 OS 版本中编译和运行，具体 OS 版本请参见 [Kmesh 支持系统](https://github.com/kmesh-net/kmesh/blob/main/docs/kmesh_support.md)。

## 构建

### 先决条件

- 安装 Docker 引擎

  ```sh
  sudo apt-get update
  (可选)sudo apt-get remove docker docker-engine docker.io
  sudo apt install docker.io
  ```

  您可以检查 Docker 版本以确保 Docker 已安装。

  ```sh
  docker version
  Client: Docker Engine - Community
  Version:           26.0.1
  API version:       1.45
  Go version:        go1.21.9
  Git commit:        d260a54
  Built:             Thu Apr 11 10:53:21 2024
  OS/Arch:           linux/amd64
  Context:           default

  Server: Docker Engine - Community
  Engine:
    Version:          26.0.1
    API version:      1.45 (minimum version 1.24)
    Go version:       go1.21.9
    Git commit:       60b9add
    Built:            Thu Apr 11 10:53:21 2024
    OS/Arch:          linux/amd64
    Experimental:     false
  containerd:
    Version:          1.6.31
    GitCommit:        e377cd56a71523140ca6ae87e30244719194a521
  runc:
    Version:          1.1.12
    GitCommit:        v1.1.12-0-g51d5e94
  docker-init:
    Version:          0.19.0
    GitCommit:        de40ad0
  ```

- 下载 Kmesh-build 镜像

  要编译 Kmesh 镜像，您需要准备 Kmesh 源代码和 Kmesh-build 镜像。可以使用以下命令获取镜像：

  ```sh
  docker pull ghcr.io/kmesh-net/kmesh-build-x86:latest
  ```

  注意：`Kmesh-build` 镜像需要与源代码版本匹配。

### 从源代码构建 Kmesh

从 GitHub 克隆源代码。

```sh
git clone https://github.com/kmesh-net/kmesh.git
```

代码编译

- 通过 build-image 编译 Kmesh

  ```sh
  cd kmesh/
  make build
  ```

- 通过脚本编译 Kmesh

  Kmesh 也提供通过脚本编译的方式

  ```sh
  [root@dev] ./kmesh_compile.sh
  ```

  注意，如果您使用脚本编译，需要确保您的 OS 系统版本是 [Kmesh 支持系统](https://github.com/kmesh-net/kmesh/blob/main/docs/kmesh_support.md) 中的一个！

Kmesh 编译完成后，构建产物将输出到 `out` 目录。

```bash
ls out/amd64/
kmesh-daemon       libbpf.so    libbpf.so.0.8.1       libkmesh_deserial.so  libprotobuf-c.so.1      mdacore
kmesh-cni  libboundscheck.so  libbpf.so.0  libkmesh_api_v2_c.so  libprotobuf-c.so      libprotobuf-c.so.1.0.0
```

### 构建 Docker 镜像

在 Kmesh 源代码目录中执行 `make docker`。

用户可以指定构建参数，如下例所示：

```sh
用户自定义 HUB、TARGET、TAG 值。如果未指定，将使用默认值。
HUB=ghcr.io/kmesh-net
TARGET=kmesh
TAG= #git sha

[root@dev docker] make docker
...
Successfully tagged ghcr.io/kmesh-net/kmesh:b68790eb07830e757f4ce6d1c478d0046ee79730

[root@dev docker] make docker HUB=ghcr.io/kmesh-net TARGET=kmesh TAG=latest
...
Successfully tagged ghcr.io/kmesh-net/kmesh:latest
```

检查本地镜像仓库中现有的 Kmesh 镜像：

```sh
[root@dev docker]# docker images ls
REPOSITORY                          TAG                                        IMAGE ID            CREATED             SIZE
ghcr.io/kmesh-net/kmesh             latest                                     71aec5898c44        About an hour ago   506MB
```

### 编译清理

您可以使用以下命令清理二进制文件。

```sh
[root@dev] make clean
```
