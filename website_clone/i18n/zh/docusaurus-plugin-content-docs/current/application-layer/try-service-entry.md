---
sidebar_position: 5
title: 尝试 Service Entry
---

Service Entry 允许您将外部服务添加到 Istio 的内部服务注册表中，使网格中的服务能够访问和路由到这些手动指定的服务。本指南将向您展示如何使用 Service Entry 配置对外部服务的访问。

## 准备工作

在开始之前，请确保完成以下步骤：

1. **使默认命名空间由 Kmesh 管理**
2. **部署 Httpbin 作为示例应用程序，并部署 Sleep 作为 curl 客户端**
3. **为默认命名空间安装 waypoint**

   _以上步骤的详细说明可以参考 [安装 Waypoint | Kmesh](/i18n/zh/docusaurus-plugin-content-docs/current/application-layer/install_waypoint.md#准备工作)_

## 验证环境设置

确认 httpbin 和 sleep 应用程序已正常运行：

```bash
kubectl get pods
```

您应该看到两个服务都处于 Running 状态：

```bash
NAME                       READY   STATUS    RESTARTS   AGE
httpbin-6f4464f6c5-h9x2p   1/1     Running   0          30s
sleep-9454cc476-86vgb      1/1     Running   0          5m
```

## 配置 Service Entry

我们将创建一个 Service Entry 来定义一个虚拟的外部服务，该服务实际上会将流量路由到集群内的 httpbin 服务：

```bash
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: external-fake-svc
  namespace: default
spec:
  exportTo:
    - "*"
  hosts:
    - kmesh-fake.com
  ports:
    - name: http
      number: 80
      protocol: HTTP
  endpoints:
    - address: httpbin.default.svc.cluster.local
      ports:
        http: 8000
  resolution: DNS
EOF
```

此配置的含义：

- `hosts`: 定义虚拟主机名 `kmesh-fake.com`
- `ports`: 指定服务监听的端口和协议
- `endpoints`: 实际的后端服务地址（这里指向集群内的 httpbin 服务）
- `resolution`: DNS 解析类型

## 测试 Service Entry 配置

配置完成后，我们可以通过以下测试验证 Service Entry 是否正常工作：

### 1. 基础连通性测试

测试访问虚拟外部服务：

```bash
kubectl exec deploy/sleep -- curl -s http://kmesh-fake.com/headers
```

您应该看到来自 httpbin 服务的响应，注意 Host 头已经变成了我们定义的虚拟主机名：

```json
{
  "headers": {
    "Accept": "*/*",
    "Host": "kmesh-fake.com",
    "User-Agent": "curl/8.16.0"
  }
}
```

### 2. 详细请求信息验证

获取完整的请求信息：

```bash
kubectl exec deploy/sleep -- curl -s http://kmesh-fake.com/get
```

输出显示请求被成功路由到 httpbin 服务：

```json
{
  "args": {},
  "headers": {
    "Accept": "*/*", 
    "Host": "kmesh-fake.com",
    "User-Agent": "curl/8.16.0"
  },
  "origin": "10.244.1.6",
  "url": "http://kmesh-fake.com/get"
}
```

### 3. HTTP 状态码测试

测试不同的 HTTP 状态码响应：

```bash
# 测试正常状态码
kubectl exec deploy/sleep -- curl -s http://kmesh-fake.com/status/200

# 测试特定状态码并显示返回码
kubectl exec deploy/sleep -- curl -s -o /dev/null -w "%{http_code}\n" http://kmesh-fake.com/status/418
```

第二个命令应该返回 HTTP 状态码：

```txt
418
```

### 4. 响应头检查

检查完整的响应头信息：

```bash
kubectl exec deploy/sleep -- curl -IsS http://kmesh-fake.com/headers
```

您应该看到包含 Envoy 代理和路由信息的响应头：

```txt
HTTP/1.1 200 OK
server: envoy
date: Wed, 08 Oct 2025 07:51:51 GMT
content-type: application/json
content-length: 78
access-control-allow-origin: *
access-control-allow-credentials: true
x-envoy-upstream-service-time: 1
x-envoy-decorator-operation: httpbin.default.svc.cluster.local:8000/*
```

## 高级用例：配置真实外部服务

除了上面演示的将虚拟主机映射到集群内服务，您还可以配置访问真实的外部服务。

### 创建外部服务配置

创建一个 Service Entry 来访问真实的外部 httpbin.org 服务：

```bash
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: external-httpbin-org
  namespace: default
spec:
  hosts:
    - httpbin.org
  ports:
    - number: 80
      name: http
      protocol: HTTP
  resolution: DNS
EOF
```

此配置允许网格内的服务直接访问外部的 httpbin.org。

### 测试外部服务访问

测试对真实外部服务的访问：

```bash
kubectl exec deploy/sleep -- curl -s http://httpbin.org/headers
```

您应该看到来自真实 httpbin.org 服务的响应：

```json
{
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.16.0"
  }
}
```

## 清理资源

完成测试后，删除创建的 Service Entry 资源：

```bash
kubectl delete serviceentry external-fake-svc -n default
kubectl delete serviceentry external-httpbin-org -n default
```

如果您不打算继续后续的实验，请参考 [安装 Waypoint/清理](/i18n/zh/docusaurus-plugin-content-docs/current/application-layer/install_waypoint.md#清理) 部分的说明来删除 waypoint 并清理应用程序。

## 总结

通过本指南，您学习了如何：

1. 使用 Service Entry 将外部服务添加到 Istio 服务网格
2. 配置虚拟主机名映射到集群内服务
3. 配置对真实外部服务的访问
4. 验证和测试 Service Entry 配置的有效性

Service Entry 是 Istio 中管理外部服务访问的重要工具，它提供了对外部依赖的可见性和控制能力。
