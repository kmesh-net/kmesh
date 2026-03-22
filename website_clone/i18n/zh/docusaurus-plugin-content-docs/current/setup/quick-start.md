---
title: 快速入门
description: 本指南可帮助您快速安装 Kmesh。
sidebar_position: 1
---

# 快速入门指南

本指南可让您快速安装 Kmesh。

## 前提条件

在安装 Kmesh 之前，请确保您的环境满足以下要求：

| 要求       | 版本  | 备注                    |
| ---------- | ----- | ----------------------- |
| Kubernetes | 1.26+ | 在 1.26-1.29 上测试通过 |
| Istio      | 1.22+ | 在 1.23-1.25 上测试通过 (需要环境模式) |
| Helm       | 3.0+  | 用于 helm 安装          |
| 内存       | 4GB+  | 建议最小配置            |
| CPU        | 2 核  | 建议最小配置            |
| 内核       | 5.10+ | 支持 eBPF               |

## 准备工作

Kmesh 需要在 Kubernetes 集群上运行。目前支持 Kubernetes 1.26+ 版本。我们建议使用 [kind](https://kind.sigs.k8s.io/docs/user/quick-start/) 快速提供 Kubernetes 集群（我们提供了一个[文档](develop-with-kind/)用于使用 kind 开发和部署 Kmesh）。当然，您也可以使用 [minikube](https://minikube.sigs.k8s.io/docs/) 等其他方式创建 Kubernetes 集群。

目前，Kmesh 使用 [istio](https://istio.io/) 作为其控制平面。在安装 Kmesh 之前，请安装 Istio 控制平面。我们建议安装 istio 环境模式，因为 Kmesh 的 `ads-v2` 模式需要它。详情请参阅 [ambient mode istio](https://istio.io/latest/docs/ops/ambient/getting-started/)。

您可以使用以下命令查看 istio 安装结果：

```shell
kubectl get po -n istio-system
NAME                      READY   STATUS    RESTARTS   AGE
istio-cni-node-xbc85      1/1     Running   0          18h
istiod-5659cfbd55-9s92d   1/1     Running   0          18h
ztunnel-4jlvv             1/1     Running   0          18h
```

> **注意**：要使用路径点，您需要安装 Kubernetes Gateway API CRD，大多数 Kubernetes 集群默认不安装：

```shell
kubectl get crd gateways.gateway.networking.k8s.io &> /dev/null || \
  { kubectl kustomize "github.com/kubernetes-sigs/gateway-api/config/crd/experimental?ref=444631bfe06f3bcca5d0eadf1857eac1d369421d" | kubectl apply -f -; }
```

### 仅安装 Istiod

按照上述步骤安装环境模式 istio 将安装额外的 istio 组件。

下面提供仅安装 `istiod` 作为 Kmesh 控制平面的过程。

#### 安装 Istio CRD

```shell
helm repo add istio https://istio-release.storage.googleapis.com/charts
helm repo update
```

使用发布名称 `istio-base` 安装图表：

```shell
kubectl create namespace istio-system
helm install istio-base istio/base -n istio-system
```

#### 安装 Istiod

使用发布名称 `istiod` 安装图表：

```shell
helm install istiod istio/istiod --namespace istio-system --version 1.24.0 --set pilot.env.PILOT_ENABLE_AMBIENT=true
```

> **重要：** 必须设置 `pilot.env.PILOT_ENABLE_AMBIENT=true`。否则 Kmesh 将无法与 istiod 建立 grpc 链接！ 如果想要使用 Waypoint 功能，您的 istiod 版本应该为 1.23~1.25。

安装 istiod 后，是时候安装 Kubernetes Gateway API CRD 了。

```shell
kubectl get crd gateways.gateway.networking.k8s.io &> /dev/null || \
  { kubectl kustomize "github.com/kubernetes-sigs/gateway-api/config/crd/experimental?ref=444631bfe06f3bcca5d0eadf1857eac1d369421d" | kubectl apply -f -; }
```

## 安装 Kmesh

我们提供多种安装 Kmesh 的方式：

### 选项 1：从 Helm 安装

```shell
helm install kmesh ./deploy/charts/kmesh-helm -n kmesh-system --create-namespace
```

### 选项 2：从 Yaml 安装

```shell
kubectl create namespace kmesh-system
kubectl apply -f ./deploy/yaml/
```

您可以使用以下命令确认 Kmesh 的状态：

```shell
kubectl get pod -n kmesh-system
NAME          READY   STATUS    RESTARTS   AGE
kmesh-v2frk   1/1     Running   0          18h
```

查看 Kmesh 服务的运行状态：

```log
time="2024-04-25T13:17:40Z" level=info msg="bpf Start successful" subsys=manager
time="2024-04-25T13:17:40Z" level=info msg="controller Start successful" subsys=manager
time="2024-04-25T13:17:40Z" level=info msg="dump StartServer successful" subsys=manager
time="2024-04-25T13:17:40Z" level=info msg="start write CNI config\n" subsys="cni installer"
time="2024-04-25T13:17:40Z" level=info msg="kmesh cni use chained\n" subsys="cni installer"
time="2024-04-25T13:17:41Z" level=info msg="Copied /usr/bin/kmesh-cni to /opt/cni/bin." subsys="cni installer"
time="2024-04-25T13:17:41Z" level=info msg="kubeconfig either does not exist or is out of date, writing a new one" subsys="cni installer"
time="2024-04-25T13:17:41Z" level=info msg="wrote kubeconfig file /etc/cni/net.d/kmesh-cni-kubeconfig" subsys="cni installer"
time="2024-04-25T13:17:41Z" level=info msg="cni config file: /etc/cni/net.d/10-kindnet.conflist" subsys="cni installer"
time="2024-04-25T13:17:41Z" level=info msg="command Start cni successful" subsys=manager
```

## 验证安装

安装 Kmesh 后，验证所有组件是否正常运行：

### 1. 验证核心组件

检查 Kmesh pod 状态：

```shell
kubectl get pod -n kmesh-system
NAME          READY   STATUS    RESTARTS   AGE
kmesh-v2frk   1/1     Running   0          18h
```

检查 Istio 组件：

```shell
kubectl get pods -n istio-system
NAME                      READY   STATUS    RESTARTS   AGE
istiod-5659cfbd55-9s92d   1/1     Running   0          18h
```

### 2. 验证 Kmesh 服务日志

检查成功初始化消息：

```shell
kubectl logs -n kmesh-system $(kubectl get pods -n kmesh-system -o jsonpath='{.items.metadata.name}')
```

查找这些关键消息：

- "bpf Start successful"
- "controller Start successful"
- "dump StartServer successful"
- "command Start cni successful"

### 3. 验证 CNI 配置

检查 CNI 二进制安装：

```shell
ls -l /opt/cni/bin/kmesh-cni
```

验证 CNI 配置：

```shell
cat /etc/cni/net.d/kmesh-cni-kubeconfig
```

### 4. 验证 Pod 集成

部署测试 pod 并验证 Kmesh 注解：

```shell
kubectl describe po <pod-name> | grep Annotations
Annotations:      kmesh.net/redirection: enabled
```

### 5. 验证服务连接

使用 sleep pod 测试服务访问：

```shell
kubectl exec sleep-7656cf8794-xjndm -c sleep -- curl -IsS "http://httpbin:8000/status/200"
```

预期响应应显示 HTTP 200 OK 状态。

## 更改 Kmesh 启动模式

Kmesh 支持两种启动模式：`ads-v2` 和 `ads-v1`。

具体使用的模式在 deploy/charts/kmesh-helm/values.yaml 中定义，我们可以在该文件中修改启动参数。

```yaml
......
    containers:
      kmeshDaemonArgs: "--mode=ads-v2 --enable-bypass=false"
......
```

我们可以使用以下命令进行修改：

```shell
sed -i 's/--mode=ads-v2/--mode=ads-v1/' deploy/charts/kmesh-helm/values.yaml
```

## 部署示例应用

Kmesh 可以管理带有标签 `istio.io/dataplane-mode=Kmesh` 的命名空间中的 pod，同时该 pod 不应具有 `istio.io/dataplane-mode=none` 标签。

```shell
# 为指定命名空间启用 Kmesh
kubectl label namespace default istio.io/dataplane-mode=Kmesh
```

应用以下配置以部署 sleep 和 httpbin：

```shell
kubectl apply -f ./samples/httpbin/httpbin.yaml

kubectl apply -f ./samples/sleep/sleep.yaml
```

检查应用状态：

```shell
kubectl get pod
NAME                                      READY   STATUS    RESTARTS   AGE
httpbin-65975d4c6f-96kgw                  1/1     Running   0          3h38m
sleep-7656cf8794-8tp9n                    1/1     Running   0          3h38m
```

您可以通过查看 pod 的注解来确认 pod 是否由 Kmesh 管理。

```shell
kubectl describe po httpbin-65975d4c6f-96kgw | grep Annotations

Annotations:      kmesh.net/redirection: enabled
```

## 测试服务访问

在应用程序由 Kmesh 管理后，我们可以测试它们是否仍能成功通信。

```shell
kubectl exec sleep-7656cf8794-xjndm -c sleep -- curl -IsS "http://httpbin:8000/status/200"

HTTP/1.1 200 OK
Server: gunicorn/19.9.0
Date: Sun, 28 Apr 2024 07:31:51 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Content-Length: 0
```

注意：10.244.0.21 是 httpbin 的 IP

## 清理

如果您不想再使用 Kmesh 管理应用程序，可以从命名空间中移除标签。

```shell
kubectl label namespace default istio.io/dataplane-mode-
kubectl delete pod httpbin-65975d4c6f-96kgw sleep-7656cf8794-8tp9n
kubectl describe pod httpbin-65975d4c6f-h2r99 | grep Annotations

Annotations:      <none>
```

### 删除 Kmesh

如果您使用 helm 安装了 Kmesh：

```shell
helm uninstall kmesh -n kmesh-system
kubectl delete ns kmesh-system
```

如果您使用 yaml 安装了 Kmesh：

```shell
kubectl delete -f ./deploy/yaml/
```

要移除 sleep 和 httpbin 应用程序：

```shell
kubectl delete -f samples/httpbin/httpbin.yaml
kubectl delete -f samples/sleep/sleep.yaml
```

如果您安装了 Gateway API CRD，请移除它们：

```shell
kubectl kustomize "github.com/kubernetes-sigs/gateway-api/config/crd/experimental?ref=444631bfe06f3bcca5d0eadf1857eac1d369421d" | kubectl delete -f -
```
