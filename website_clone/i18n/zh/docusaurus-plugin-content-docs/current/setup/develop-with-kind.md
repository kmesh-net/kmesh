---
title: 使用 Kind 进行部署/开发
sidebar_position: 2
---

# 使用 Kind 部署/开发

[Kind](https://github.com/kubernetes-sigs/kind) 是一种方便的工具，用于在本地快速部署 kubernetes 集群。我们可以使用 `kind` 创建 `istio` 集群并部署 `kmesh`。

## 在 Kind 中部署 Kmesh

让我们从设置所需环境开始。您可以按照以下步骤操作：

### 安装 kind

安装 `kind` 非常简单，因为它只是一个二进制文件。您可以根据 [github 发布页面](https://github.com/kubernetes-sigs/kind/releases) 上的版本和架构选择正确的文件。以 `linux` + `amd64` 为例：

```shell
wget -O kind https://github.com/kubernetes-sigs/kind/releases/download/v0.23.0/kind-linux-amd64
chmod +x kind
mv kind /usr/bin/
```

### 使用 kind 创建 Kubernetes 集群

您可以参考 [istio 官方文档](https://istio.io/latest/docs/setup/platform-setup/kind/)。

如果您想指定多个工作节点或节点镜像，可以：

```shell
kind create cluster --image=kindest/node:v1.30.0 --config=- <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ambient
nodes:
- role: control-plane
- role: worker
- role: worker
EOF
```

### 安装 istioctl

```shell
ISTIO_VERSION="1.24.0" # 如果您希望使用 Waypoint 功能，istio 版本应该为 1.23 ~ 1.25

curl -L https://istio.io/downloadIstio | ISTIO_VERSION="${ISTIO_VERSION}" sh - && \
cd "istio-${ISTIO_VERSION}/bin" && \
chmod +x istioctl && \
mv istioctl /usr/bin/
```

### 使用 istioctl 安装 istio 组件

```shell
istioctl install
```

如果您想在 `workload` 模式下使用 `Kmesh`，您应该以 [环境模式](https://istio.io/latest/docs/ambient/overview/) 部署 `istio`，通过添加一个额外的标志：

```shell
istioctl install --set profile=ambient
```

### 安装 kubectl

请按照官方指南操作：[在 Linux 上安装和设置 kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)。

### 部署 Kmesh

现在，您已准备好在本地集群中部署 Kmesh。请随时按照 [Kmesh 快速入门](/i18n/zh/docusaurus-plugin-content-docs/current/setup/quick-start.md) 进行操作。

## 在 Kind 中开发 Kmesh

您可以按照以下步骤在 kind 中进行开发：

### 在本地构建代码和 docker 镜像

```shell
make docker
```

这将启动一个名为 `kmesh-build` 的 docker 容器来构建您的代码。然后，它将构建相应的 docker 镜像。

您也可以分别执行此操作：

#### 在本地构建代码

```shell
make build
```

#### 在本地构建 docker 镜像

```shell
docker build --build-arg arch=amd64 -f build/docker/dockerfile -t $image_name .
```

您应该指定 `image_name`。

### 将镜像加载到每个集群节点

```shell
kind load docker-image $image_name --name $cluster_name
```

您应该指定 `image_name` 和 `cluster_name`。

### 编辑 Kmesh daemonset

Kmesh 守护进程作为 kubernetes `Daemonset` 运行。您应该修改 daemonset 的配置，触发重新部署。

```shell
kubectl edit ds kmesh -n kmesh-system
```

这将打开一个编辑器，您可以在此处修改镜像。

您可以通过以下方式检查 Kmesh 守护进程是否都在运行：

```shell
kubectl get po -n kmesh-system -w
```

### 检查日志

您可以通过以下方式检查 Kmesh 守护进程的日志：

```shell
kubectl logs $kmesh_pod_name -n kmesh-system
```

`kmesh_pod_name` 是指定 Kmesh pod 的名称。

您可以通过以下方式更改日志级别：

```shell
kubectl exec -it $kmesh_pod_name -n kmesh-system -- kmesh-daemon log --set default:debug
```

特别是，对于 bpf 日志：

```shell
kubectl exec -it $kmesh_pod_name -n kmesh-system -- kmesh-daemon log --set bpf:debug
```

您可以使用 `uname -r` 检查内核版本。如果高于 `5.13.0`，bpf 日志将被推送到用户空间。我们可以在日志文件中查看它们（带有 `subsys=ebpf`）。否则，您应该使用 `bpftool` 检查它们：

```shell
bpftool prog tracelog
```

### 清理

构建过程将修改一些与配置相关的文件，如果您想将代码推送到 github，请使用：

```shell
make clean
```

在执行 `git add` 命令之前清理这些更改。

## 参考

- 入门指南：https://istio.io/latest/docs/ambient/getting-started
- Istio Ambient Mesh 入门：https://istio.io/latest/blog/2022/get-started-ambient
- 使用 Istioctl 安装：https://istio.io/latest/docs/setup/install/istioctl
