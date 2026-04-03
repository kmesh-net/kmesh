---
title: 运行单元测试
sidebar_position: 1
---

# 运行单元测试

直接在操作系统中编译 Kmesh 需要特定的 [OS 版本](https://github.com/kmesh-net/kmesh/blob/main/docs/kmesh_support.md)。因此，为了让所有操作系统都能运行 Kmesh 的单元测试（UT），Kmesh 提供了两种方法。一种是在 Docker 中运行 Go 单元测试，另一种是在本地运行 Go 单元测试。

不支持的内核版本的开发者可以通过脚本在 Docker 中运行 Go 单元测试。支持版本的开发者可以通过脚本在本地运行 Go 单元测试。

```sh
cd $(Kmesh root directory)

# 通过 Docker 运行 Kmesh 单元测试
./hack/run-ut.sh --docker

# 在本地运行 Kmesh 单元测试
./hack/run-ut.sh --local
```

或者，您可以通过 `make test` 执行测试：

```sh
# 通过 Docker 运行 Kmesh 单元测试
make test RUN_IN_CONTAINER=1

# 在本地运行 Kmesh 单元测试
make test RUN_IN_CONTAINER=0
```

## 单元测试

本节描述 Kmesh 的单元测试设置，以便开发人员可以不使用脚本运行单元测试。

由于 Kmesh 使用 eBPF，您在运行与 Kmesh 相关的单元测试时需要设置一些环境变量。

```sh
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib:$ROOT_DIR/api/v2-c:$ROOT_DIR/bpf/deserialization_to_bpf_map
export PKG_CONFIG_PATH=$ROOT_DIR/mk
```

设置 `LD_LIBRARY_PATH` 以便系统可以找到 .so 文件。

设置 `PKG_CONFIG_PATH` 以便系统可以找到 Kmesh 编译的 .pc 文件。

除此之外，您还可能遇到 C 头文件未找到的错误。可以通过设置 `C_INCLUDE_PATH` 来解决此类错误。Kmesh 所需的头文件保存在 [bpf](https://github.com/kmesh-net/kmesh/tree/main/bpf) 文件夹中。

注意 **多个头文件** 问题。

除了上述问题，由于 Kmesh 单元测试使用 gomonkey，在 Go 编译优化过程中可能会出现 monkey 的函数被内联的情况。

我们可以通过在 go test 执行时添加以下参数来解决这个问题：

```bash
-gcflags="all=-N -l"
```
