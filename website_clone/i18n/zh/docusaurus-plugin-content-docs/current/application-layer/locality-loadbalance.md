---
sidebar_position: 9
title: 地域负载均衡
---

本文档介绍如何在 Kmesh 中使用 Istio 的地域负载均衡功能。

> 当前的 Kmesh 地域负载均衡处于 L4 级别，仅支持[地域故障转移](https://istio.io/latest/docs/tasks/traffic-management/locality-load-balancing/failover/)。

## 什么是地域负载均衡？

地域定义了网格中工作负载实例的地理位置。服务网格中的地域负载均衡通过根据服务实例的位置智能路由流量，有助于提高服务的可用性和性能。

我们强烈建议您首先阅读 https://istio.io/latest/docs/tasks/traffic-management/locality-load-balancing/ 以了解地域负载均衡的概念。

## Kmesh 支持的模式和配置方法

目前，Istio 的 ambient 模式仅支持通过配置特定字段来指定固定的地域负载均衡策略。这包括两种模式：PreferClose 和 Local。

### 1. PreferClose

一种故障转移模式，使用 NETWORK、REGION、ZONE 和 SUBZONE 作为 routingPreference。

- 使用 `spec.trafficDistribution`（k8s >= beta [1.31.0](https://kubernetes.io/docs/concepts/services-networking/service/), istio >= [1.23.1](https://istio.io/latest/news/releases/1.23.x/announcing-1.23/)）

  ```yaml
  spec:
    trafficDistribution: # spec.trafficDistribution
      preferClose: true
  ```

- 使用 annotation

  ```yaml
  metadata:
    annotations:
      networking.istio.io/traffic-distribution: PreferClose
  ```

### 2. Local

一种严格模式，仅匹配当前 NODE。

- spec.internalTrafficPolicy: Local (k8s >= beta 1.24 或 >= 1.26)

  ```yaml
  spec:
    internalTrafficPolicy: Local
  ```

## 实验测试

### 准备环境

- 参考[在 kind 中开发](/i18n/zh/docusaurus-plugin-content-docs/current/setup/develop-with-kind.md)
- 我们在集群中准备了三个节点
- istio >= 1.23.1
- k8s >= 1.31.0
- 确保 sidecar 注入已禁用：`kubectl label namespace default istio-injection-`
- 所需镜像：
  - docker.io/istio/examples-helloworld-v1
  - curlimages/curl

```yaml
kind create cluster --image=kindest/node:v1.31.0 --config=- <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ambient
nodes:
- role: control-plane
- role: worker
- role: worker
- role: worker
EOF
```

### 1. 为节点分配地域信息

```bash
kubectl label node ambient-worker topology.kubernetes.io/region=region
kubectl label node ambient-worker topology.kubernetes.io/zone=zone1
kubectl label node ambient-worker topology.kubernetes.io/subzone=subzone1
```

```bash
kubectl label node ambient-worker2 topology.kubernetes.io/region=region
kubectl label node ambient-worker2 topology.kubernetes.io/zone=zone1
kubectl label node ambient-worker2 topology.kubernetes.io/subzone=subzone2
```

```bash
kubectl label node ambient-worker3 topology.kubernetes.io/region=region
kubectl label node ambient-worker3 topology.kubernetes.io/zone=zone2
kubectl label node ambient-worker3 topology.kubernetes.io/subzone=subzone3
```

### 2. 启动测试服务器

- 创建 `sample` 命名空间

  ```bash
  kubectl create namespace sample
  ```

- 运行一个服务

  ```yaml
  kubectl apply -n sample -f - <<EOF
  apiVersion: v1
  kind: Service
  metadata:
    name: helloworld
    labels:
      app: helloworld
      service: helloworld
  spec:
    ports:
    - port: 5000
      name: http
    selector:
      app: helloworld
    trafficDistribution: PreferClose
  EOF
  ```

- 在 ambient-worker 上启动一个服务实例

  ```yaml
  kubectl apply -n sample -f - <<EOF
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: helloworld-region.zone1.subzone1
    labels:
      app: helloworld
      version: region.zone1.subzone1
  spec:
    replicas: 1
    selector:
      matchLabels:
        app: helloworld
        version: region.zone1.subzone1
    template:
      metadata:
        labels:
          app: helloworld
          version: region.zone1.subzone1
      spec:
        containers:
        - name: helloworld
          env:
          - name: SERVICE_VERSION
            value: region.zone1.subzone1
          image: docker.io/istio/examples-helloworld-v1
          resources:
            requests:
              cpu: "100m"
          imagePullPolicy: IfNotPresent
          ports:
          - containerPort: 5000
        nodeSelector:
          kubernetes.io/hostname: ambient-worker
  EOF
  ```

- 在 ambient-worker2 上启动一个服务实例

  ```yaml
  kubectl apply -n sample -f - <<EOF
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: helloworld-region.zone1.subzone2
    labels:
      app: helloworld
      version: region.zone1.subzone2
  spec:
    replicas: 1
    selector:
      matchLabels:
        app: helloworld
        version: region.zone1.subzone2
    template:
      metadata:
        labels:
          app: helloworld
          version: region.zone1.subzone2
      spec:
        containers:
        - name: helloworld
          env:
          - name: SERVICE_VERSION
            value: region.zone1.subzone2
          image: docker.io/istio/examples-helloworld-v1
          resources:
            requests:
              cpu: "100m"
          imagePullPolicy: IfNotPresent
          ports:
          - containerPort: 5000
        nodeSelector:
          kubernetes.io/hostname: ambient-worker2
  EOF
  ```

- 在 ambient-worker3 上启动一个服务实例

  ```yaml
  kubectl apply -n sample -f - <<EOF
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: helloworld-region.zone2.subzone3
    labels:
      app: helloworld
      version: region.zone2.subzone3
  spec:
    replicas: 1
    selector:
      matchLabels:
        app: helloworld
        version: region.zone2.subzone3
    template:
      metadata:
        labels:
          app: helloworld
          version: region.zone2.subzone3
      spec:
        containers:
        - name: helloworld
          env:
          - name: SERVICE_VERSION
            value: region.zone2.subzone3
          image: docker.io/istio/examples-helloworld-v1
          resources:
            requests:
              cpu: "100m"
          imagePullPolicy: IfNotPresent
          ports:
          - containerPort: 5000
        nodeSelector:
          kubernetes.io/hostname: ambient-worker3
  EOF
  ```

### 3. 在客户端上测试

- 在 ambient-worker 上启动测试客户端

  ```yaml
  kubectl apply -n sample -f - <<EOF
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: sleep
  spec:
    replicas: 1
    selector:
      matchLabels:
        app: sleep
    template:
      metadata:
        labels:
          app: sleep
      spec:
        terminationGracePeriodSeconds: 0
        containers:
        - name: sleep
          image: curlimages/curl
          command: ["/bin/sleep", "infinity"]
          imagePullPolicy: IfNotPresent
          volumeMounts:
          - mountPath: /etc/sleep/tls
            name: secret-volume
        volumes:
        - name: secret-volume
          secret:
            secretName: sleep-secret
            optional: true
        nodeSelector:
          kubernetes.io/hostname: ambient-worker
  EOF
  ```

- 测试访问

  ```bash
  kubectl exec -n sample "$(kubectl get pod -n sample -l app=sleep -o jsonpath='{.items[0].metadata.name}')" -c sleep -- curl -sSL "http://helloworld:5000/hello"
  ```

  输出来自当前与 ambient-worker 共置的 helloworld-region.zone1.subzone1：

  ```text
  Hello version: region.zone1.subzone1, instance: helloworld-region.zone1.subzone1-6d6fdfd856-9dhv8
  ```

- 删除 ambient-worker 上的服务并测试故障转移

  ```bash
  kubectl delete deployment -n sample helloworld-region.zone1.subzone1
  ```

  ```bash
  kubectl exec -n sample "$(kubectl get pod -n sample -l app=sleep -o jsonpath='{.items[0].metadata.name}')" -c sleep -- curl -sSL "http://helloworld:5000/hello"
  ```

  输出为 helloworld-region.zone1.subzone2，流量已发生故障转移：

  ```text
  Hello version: region.zone1.subzone2, instance: helloworld-region.zone1.subzone2-948c95bdb-7p6zb
  ```

- 将 ambient-worker3 的地域标签更改为与 worker2 相同并测试

  ```bash
  kubectl label node ambient-worker3 topology.kubernetes.io/zone=zone1 --overwrite
  kubectl label node ambient-worker3 topology.kubernetes.io/subzone=subzone2 --overwrite
  ```

  删除 helloworld-region.zone2.subzone3 并重新应用开发 pod 如下，然后运行测试：

  ```bash
  kubectl delete deployment -n sample helloworld-region.zone2.subzone3

  kubectl apply -n sample -f - <<EOF
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: helloworld-region.zone1.subzone2-worker3
    labels:
      app: helloworld
      version: region.zone1.subzone2-worker3
  spec:
    replicas: 1
    selector:
      matchLabels:
        app: helloworld
        version: region.zone1.subzone2-worker3
    template:
      metadata:
        labels:
          app: helloworld
          version: region.zone1.subzone2-worker3
      spec:
        containers:
        - name: helloworld
          env:
          - name: SERVICE_VERSION
            value: region.zone1.subzone2-worker3
          image: docker.io/istio/examples-helloworld-v1
          resources:
            requests:
              cpu: "100m"
          imagePullPolicy: IfNotPresent
          ports:
          - containerPort: 5000
        nodeSelector:
          kubernetes.io/hostname: ambient-worker3
  EOF
  ```

  多次测试：

  ```bash
  kubectl exec -n sample "$(kubectl get pod -n sample -l app=sleep -o jsonpath='{.items[0].metadata.name}')" -c sleep -- curl -sSL "http://helloworld:5000/hello"
  ```

  输出随机显示 helloworld-region.zone1.subzone2 和 helloworld-region.zone1.subzone2-worker3：

  ```text
  Hello version: region.zone1.subzone2-worker3, instance: helloworld-region.zone1.subzone2-worker3-6d6fdfd856-6kd2s
  Hello version: region.zone1.subzone2, instance: helloworld-region.zone1.subzone2-948c95bdb-7p6zb
  Hello version: region.zone1.subzone2, instance: helloworld-region.zone1.subzone2-948c95bdb-7p6zb
  Hello version: region.zone1.subzone2-worker3, instance: helloworld-region.zone1.subzone2-worker3-6d6fdfd856-6kd2s
  Hello version: region.zone1.subzone2, instance: helloworld-region.zone1.subzone2-948c95bdb-7p6zb
  ```
