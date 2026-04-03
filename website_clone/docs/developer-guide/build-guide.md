---
sidebar_position: 1
title: "How to build"
---

The Kmesh needs to be compiled and built in the Linux environment with the Kmesh kernel enhancement feature. Currently, Kmesh can be compiled and run in multiple OS versions, and the specific OS versions can see [Kmesh support system](https://github.com/kmesh-net/kmesh/blob/main/docs/kmesh_support.md).

## Build

### Prerequisite

- Install docker-engine

  ```sh
  sudo apt-get update
  (optional)sudo apt-get remove docker docker-engine docker.io
  sudo apt install docker.io
  ```

  You can check the docker version to make sure that docker is installed.

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

- Download Kmesh-build image

  To compile the Kmesh image, you need to prepare the Kmesh source code and the Kmesh-build image. The image can be obtained using the following command:

  ```sh
  docker pull ghcr.io/kmesh-net/kmesh-build-x86:latest
  ```

  Note: The `Kmesh-build` image needs to match the version of the source code.

### Build Kmesh from Source

Clong the source code from github.

```sh
git clone https://github.com/kmesh-net/kmesh.git
```

Code compilation

- Compile Kmesh through build-image

  ```sh
  cd kmesh/
  make build
  ```

- Compile Kmesh through script

  Kmesh also provides a way to compile through scripts

  ```sh
  [root@dev] ./kmesh_compile.sh
  ```

  Note that if you use script to compile, you need to make sure that your os system version is one that [Kmesh supports system](https://github.com/kmesh-net/kmesh/blob/main/docs/kmesh_support.md)!

When Kmesh compilation is finish, the build artifacts will be output to the `out` directory.

```bash
ls out/amd64/
kmesh-daemon       libbpf.so    libbpf.so.0.8.1       libkmesh_deserial.so  libprotobuf-c.so.1      mdacore
kmesh-cni  libboundscheck.so  libbpf.so.0  libkmesh_api_v2_c.so  libprotobuf-c.so      libprotobuf-c.so.1.0.0
```

### Build Docker Image

Execute `make docker` in the Kmesh source code directory.

Users can specify parameters for building, as shown in the example below:

```sh
User-defined HUB, TARGET, TAG values. If not specified, default values will be used.
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

Check the existing Kmesh image in the local image repository：

```sh
[root@dev docker]# docker images ls
REPOSITORY                          TAG                                        IMAGE ID            CREATED             SIZE
ghcr.io/kmesh-net/kmesh             latest                                     71aec5898c44        About an hour ago   506MB
```

### Compilation Cleanup

You can use the following command to clean up the binaries.

```sh
[root@dev] make clean
```
