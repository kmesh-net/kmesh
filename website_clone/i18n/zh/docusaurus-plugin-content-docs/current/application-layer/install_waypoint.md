---
sidebar_position: 3
title: 安装 Waypoint
---

如果您想使用 Kmesh 的 L7 功能，安装 waypoint 是先决条件。

## 准备工作

1. **安装 Kmesh**：

   请参阅[快速入门](/i18n/zh/docusaurus-plugin-content-docs/current/setup/quick-start.md)

2. **部署示例应用程序**：

   使用 Kmesh 管理 `default` 命名空间

   ```bash
   [root@ ~]# kubectl label namespace default istio.io/dataplane-mode=Kmesh
   [root@ ~]# kubectl get namespace -L istio.io/dataplane-mode
   NAME                 STATUS   AGE   DATAPLANE-MODE
   default              Active   13d   Kmesh
   istio-system         Active   13d
   kmesh-system         Active   27h
   kube-node-lease      Active   13d
   kube-public          Active   13d
   kube-system          Active   13d
   local-path-storage   Active   13d
   ```

3. **部署 `bookinfo`**：

   ```bash
   [root@ ~]# kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/bookinfo/platform/kube/bookinfo.yaml
   ```

4. **部署 `sleep` 作为 curl 客户端**：

   ```bash
   [root@ ~]# kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/sleep/sleep.yaml
   [root@ ~]# kubectl get pods
   NAME                             READY   STATUS    RESTARTS   AGE
   details-v1-5f4d584748-bz42z      1/1     Running   0          72s
   productpage-v1-564d4686f-2rjqc   1/1     Running   0          72s
   ratings-v1-686ccfb5d8-dnzkf      1/1     Running   0          72s
   reviews-v1-86896b7648-fqm4z      1/1     Running   0          72s
   reviews-v2-b7dcd98fb-nn42q       1/1     Running   0          72s
   reviews-v3-5c5cc7b6d-q4r5h       1/1     Running   0          72s
   sleep-9454cc476-86vgb            1/1     Running   0          62s
   ```

5. **测试 `bookinfo` 按预期工作**：

   ```bash
   [root@ ~]# kubectl exec deploy/sleep -- curl -s http://productpage:9080/ | grep -o "<title>.*</title>"
   <title>Simple Bookstore App</title>
   ```

## 安装 Waypoint

Waypoint 可以在三种粒度级别使用：命名空间、服务和 Pod。您还可以在一个命名空间内为不同粒度安装多个 waypoint。下面我们将学习如何为不同粒度部署不同的 waypoint。我们可以使用 `kmeshctl waypoint` 子命令来生成或应用 waypoint。

要启用命名空间、服务或 Pod 使用 waypoint，请添加 `istio.io/use-waypoint` 标签，并将值设置为 waypoint 名称。我们还可以通过 `--image` 指定自定义的 waypoint 镜像，默认情况下为 `ghcr.io/kmesh-net/waypoint:{VERSION}`。

### 为特定服务配置 Waypoint

为服务 `reviews` 部署一个 waypoint `reviews-svc-waypoint`，这样从 Kmesh 管理的客户端到 `reviews` 的任何流量都将由 waypoint 代理调解。

```bash
[root@ ~]# kmeshctl waypoint apply --for service -n default --name=reviews-svc-waypoint

waypoint default/reviews-svc-waypoint applied
```

为 `reviews` 服务添加标签以使用 `reviews-svc-waypoint` waypoint：

```bash
[root@ ~]# kubectl label service reviews istio.io/use-waypoint=reviews-svc-waypoint

service/reviews labeled
```

waypoint 启动并运行后，Kmesh L7 功能即启用！

```bash
[root@ ~]# kubectl get pods
NAME                                      READY   STATUS    RESTARTS   AGE
details-v1-cdd874bc9-xcdnj                1/1     Running   0          30m
productpage-v1-5bb9985d4d-z8cws           1/1     Running   0          30m
ratings-v1-6484d64bbc-pkv6h               1/1     Running   0          30m
reviews-svc-waypoint-8cb4bdbf-9d5mj       1/1     Running   0          30m
reviews-v1-598f9b58fc-2rw7r               1/1     Running   0          30m
reviews-v2-5979c6fc9c-72bst               1/1     Running   0          30m
reviews-v3-7bbb5b9cf7-952d8               1/1     Running   0          30m
sleep-5577c64d7c-n7rxp                    1/1     Running   0          30m
```

### 为特定命名空间配置 Waypoint

为 `default` 命名空间部署一个默认名称为 `waypoint` 的 waypoint。通过指定 `--enroll-namespace`，命名空间将被标记为 `istio.io/use-waypoint=waypoint`。

```bash
[root@ ~]# kmeshctl waypoint apply -n default --enroll-namespace
waypoint default/waypoint applied
namespace default labels with "istio.io/use-waypoint: waypoint"
```

### 为特定 Pod 配置 Waypoint

为 Pod `reviews-v2-5979c6fc9c-72bst` 部署一个名为 `reviews-v2-pod-waypoint` 的 waypoint。

```bash
[root@ ~]# kmeshctl waypoint apply -n default --name reviews-v2-pod-waypoint --for workload
waypoint default/reviews-v2-pod-waypoint applied
# 为 `reviews-v2` Pod 添加标签以使用 `reviews-v2-pod-waypoint` waypoint。
[root@ ~]# kubectl label pod reviews-v2-5979c6fc9c-72bst istio.io/use-waypoint=reviews-v2-pod-waypoint
pod/reviews-v2-5b667bcbf8-spnnh labeled
```

现在，Kmesh 中的 Pod 发往 `reviews-v2` Pod IP 的任何请求都将通过 `reviews-v2-pod-waypoint` waypoint 进行 L7 处理和策略执行。

## 清理

如果您**不**打算探索任何后续任务，请继续执行清理步骤。

1. **移除 Waypoint**：

**移除服务的 Waypoint**

   ```bash
   [root@ ~]# kmeshctl waypoint delete reviews-svc-waypoint
   [root@ ~]# kubectl label service reviews istio.io/use-waypoint-
   ```

**移除命名空间的 Waypoint**

   ```bash
   [root@ ~]# kmeshctl waypoint delete waypoint
   [root@ ~]# kubectl label namespace default istio.io/use-waypoint-
   ```

**移除 Pod 的 Waypoint**

   ```bash
   [root@ ~]# kmeshctl waypoint delete reviews-v2-pod-waypoint
   [root@ ~]# kubectl label pod -l version=v2,app=reviews istio.io/use-waypoint-
   ```

2. **移除示例应用程序**：

   ```bash
   [root@ ~]# kubectl delete -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/bookinfo/platform/kube/bookinfo.yaml
   [root@ ~]# kubectl delete -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/sleep/sleep.yaml
   ```

3. **从 Kmesh 中移除 `default` 命名空间**：

   ```bash
   [root@ ~]# kubectl label namespace default istio.io/dataplane-mode-
   ```

## 演示

<div className="video-responsive">
  <iframe
    src="https://www.youtube.com/embed/_mnPQU5SSFo"
    frameborder="0"
    allowfullscreen
  ></iframe>
</div>
