---
sidebar_position: 5
title: 尝试流量转移
---

## 准备工作

1. **使默认命名空间由 Kmesh 管理**
2. **部署 Bookinfo 作为示例应用程序，并部署 Sleep 作为 curl 客户端**
3. **为 reviews 服务安装服务粒度的 waypoint**

_以上步骤可以参考 [安装 Waypoint | Kmesh](/i18n/zh/docusaurus-plugin-content-docs/current/application-layer/install_waypoint.md#准备工作)_

## 应用基于权重的路由

配置流量路由，将 90% 的请求发送到 `reviews v1`，10% 发送到 `reviews v2`：

```bash
[root@ ~]# kubectl apply -f -<<EOF
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: reviews
spec:
  hosts:
    - reviews
  http:
  - route:
    - destination:
        host: reviews
        subset: v1
      weight: 90
    - destination:
        host: reviews
        subset: v2
      weight: 10
---
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: reviews
spec:
  host: reviews
  trafficPolicy:
    loadBalancer:
      simple: RANDOM
  subsets:
  - name: v1
    labels:
      version: v1
  - name: v2
    labels:
      version: v2
  - name: v3
    labels:
      version: v3
EOF
```

确认大约 90% 的流量发送到 `reviews v1`：

```bash
[root@ ~]# kubectl exec deploy/sleep -- sh -c "for i in \$(seq 1 100); do curl -s http://productpage:9080/productpage | grep reviews-v.-; done"
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v2-64776cb9bd-grnd2</u>
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v1-57c85f47fb-n9llm</u>
        ...
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v2-64776cb9bd-grnd2</u>
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v2-64776cb9bd-grnd2</u>
```

## 理解发生了什么

由于 `default` 命名空间已由 Kmesh 管理，并且我们为服务 `bookinfo-reviews` 部署了 waypoint 代理，因此发送到服务 `reviews` 的所有流量都将由 Kmesh 转发到 waypoint。Waypoint 将根据我们设置的路由规则将 90% 的请求发送到 `reviews v1`，10% 发送到 `reviews v2`。

## 清理

1. **删除应用程序路由规则：**

```bash
kubectl delete virtualservice reviews
kubectl delete destinationrules reviews
```

2. **如果您不打算继续探索后续任务**  
   请参考 [安装 Waypoint/清理](/i18n/zh/docusaurus-plugin-content-docs/current/application-layer/install_waypoint.md#清理) 说明删除 waypoint 并关闭应用程序。

## 演示

<div className="video-responsive">
  <iframe
    src="https://www.youtube.com/embed/qX6qFfk4Z4k"
    frameborder="0"
    allowfullscreen
  ></iframe>
</div>
