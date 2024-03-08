# Compiling and Building Kmesh

The Kmesh needs to be compiled and built in the Linux environment with the Kmesh kernel enhancement feature. Currently, Kmesh can be compiled and run in multiple OS versions, and the specific OS versions can see [Kmesh support system](kmesh_support.md).

## build

### prerequisite

- install docker-engine

  ```sh
  [root@dev Kmesh]# yum install docker-engine
  ```

- Preparation of raw materials

  To compile the kmesh image, you need to prepare the kmesh source code and the kmesh-build image. The image can be obtained using the following command:

  Note: The `kmesh-build` image needs to match the version of the source code.
  
  ```
  docker pull ghcr.io/kmesh-net/kmesh-build-x86:latest
  ```

### build from source

- Code download

  ```sh
  [root@ ~]# git clone https://github.com/kmesh-net/kmesh.git
  ```

- Code compilation

  ```sh
  [root@dev tmp]# cd kmesh/
  [root@dev Kmesh]# make build
  ```

  Kmesh will be compiled and built within the build image, and the build artifacts will be output to the `out` directory.

  ```bash
  [root@localhost kmesh]# ls out/amd64/
  kmesh-daemon       libbpf.so    libbpf.so.0.8.1       libkmesh_deserial.so  libprotobuf-c.so.1      mdacore
  kmesh-cni  libboundscheck.so  libbpf.so.0  libkmesh_api_v2_c.so  libprotobuf-c.so      libprotobuf-c.so.1.0.0
  ```

### build docker image

- Image Creation

  Execute `make docker` in the kmesh source code directory.

  Users can specify parameters for building, as shown in the example below:

  ```sh
  User-defined HUB, TARGET, TAG values. If not specified, default values will be used.
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
  
  Check the existing Kmesh image in the local image repository：
  
  ```sh
  [root@dev docker]# docker images
  REPOSITORY                          TAG                                        IMAGE ID            CREATED             SIZE
  ghcr.io/kmesh-net/kmesh             v0.2.0                                     71aec5898c44        10 days ago         457MB
  ```
### Compilation cleanup

  ```sh
  [root@dev Kmesh]# make clean
  ```
