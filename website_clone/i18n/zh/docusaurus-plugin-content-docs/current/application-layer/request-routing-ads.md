---
sidebar_position: 1
title: 请求路由
---

本任务向您展示如何在 Kmesh 中为 HTTP 流量设置请求路由策略。

## 开始之前

- 安装 Kmesh

  - 请参考 [快速入门](/i18n/zh/docusaurus-plugin-content-docs/current/setup/quick-start.md) 并切换到内核原生(Kernel Native)模式

- 部署 fortio 应用程序

  ```bash
  kubectl apply -f samples/fortio/fortio-route.yaml
  kubectl apply -f samples/fortio/netutils.yaml
  ```

- 检查应用状态并确保服务应用由 Kmesh 管理

  ```bash
  kubectl get pod
  NAME                         READY   STATUS    RESTARTS   AGE
  fortio-v1-596b55cb8b-sfktr   1/1     Running   0          57m
  fortio-v2-76997f99f4-qjsmd   1/1     Running   0          57m
  netutils-575f5c569-lr98z     1/1     Running   0          67m

  kubectl describe pod netutils-575f5c569-lr98z | grep Annotations
  Annotations:      kmesh.net/redirection: enabled
  ```

## 测试路由配置

- 使用以下命令显示定义的路由：

  ```bash
  $ kubectl get virtualservices -o yaml
  apiVersion: v1
  items:
  - apiVersion: networking.istio.io/v1beta1
    kind: VirtualService
    metadata:
      annotations:
        kubectl.kubernetes.io/last-applied-configuration: |
          {"apiVersion":"networking.istio.io/v1alpha3","kind":"VirtualService","metadata":{"annotations":{},"name":"fortio","namespace":"default"},"spec":{"hosts":["fortio"],"http":[{"route":[{"destination":{"host":"fortio","subset":"v1"},"weight":90},{"destination":{"host":"fortio","subset":"v2"},"weight":10}]}]}}
      creationTimestamp: "2024-07-09T09:00:36Z"
      generation: 1
      name: fortio
      namespace: default
      resourceVersion: "11166"
      uid: 0a07f283-ac26-4d86-b3bd-ce6aa07dc628
    spec:
      hosts:
      - fortio
      http:
      - route:
        - destination:
            host: fortio
            subset: v1
          weight: 90
        - destination:
            host: fortio
            subset: v2
          weight: 10
  kind: List
  metadata:
    resourceVersion: ""
  ```

- 您已将 fortio 配置为 90% 路由到 fortio 服务器的 `v1` 版本

  ```bash
  $ for i in {1..20}; do kubectl exec -it $(kubectl get pod | grep netutils | awk '{print $1}') -- curl -v $(kubectl get svc -owide | grep fortio | awk '{print $3}'):80 | grep "Server:"; done
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 2
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 2
  < Server: 1
  < Server: 1
  ```

## 基于用户身份的路由

- 接下来，您将更改路由配置，以便来自特定用户的所有流量都路由到特定的服务版本。在本例中，来自名为 Jason 的用户的所有流量都将路由到服务 `fortio:v2`。

- 应用配置：

  ```bash
  kubectl apply -f samples/fortio/fortio-header.yaml
  ```

- fortio-header.yaml

  ```yaml
  apiVersion: networking.istio.io/v1alpha3
  kind: VirtualService
  metadata:
    name: fortio
  spec:
    hosts:
      - fortio
    http:
      - match:
          - headers:
              end-user:
                exact: jason
        route:
          - destination:
              host: fortio
              subset: v2
      - route:
          - destination:
              host: fortio
              subset: v1
  ```

- 验证来自服务器 1 的响应

  ```bash
  [root@localhost route]# for i in {1..10}; do kubectl exec -it $(kubectl get pod | grep netutils | awk '{print $1}') -- curl -v $(kubectl get svc -owide | grep fortio | awk '{print $3}'):80 | grep "Server:"; done
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  < Server: 1
  ```

- 使用 header 验证来自服务器 2 的响应

  ```bash
  [root@localhost route]# for i in {1..10}; do kubectl exec -it $(kubectl get pod | grep netutils | awk '{print $1}') -- curl --header "end-user:jason" -v $(kubectl get svc -owide | grep fortio | awk '{print $3}'):80 | grep "Server:"; done
  < Server: 2
  < Server: 2
  < Server: 2
  < Server: 2
  < Server: 2
  < Server: 2
  < Server: 2
  < Server: 2
  < Server: 2
  < Server: 2
  ```

## 理解发生了什么

如果未配置用户请求 header，将使用 V1。如果配置了 Jason 请求 header，将使用 V2。

## 清理

1. 删除应用程序路由规则

   ```bash
   kubectl delete -f samples/fortio/fortio-route.yaml
   kubectl delete -f samples/fortio/netutils.yaml
   ```

2. 删除 kmesh

   - 请参考 [清理](/i18n/zh/docusaurus-plugin-content-docs/current/setup/quick-start.md#清理)
