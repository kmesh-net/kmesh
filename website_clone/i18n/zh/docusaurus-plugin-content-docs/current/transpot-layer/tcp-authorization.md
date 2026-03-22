---
sidebar_position: 1
title: TCP 授权
---

本指南将向您展示如何在 Kmesh 中为 TCP 流量设置授权策略。

## 开始之前

- 了解 [AuthorizationPolicy](#authorizationpolicy) 概念  
- 安装 Kmesh  
  - 请参阅[快速入门指南](/i18n/zh/docusaurus-plugin-content-docs/current/setup/quick-start.md)  
- 部署示例应用程序并配置它们由 Kmesh 管理  
  - 请参阅[部署应用程序](/i18n/zh/docusaurus-plugin-content-docs/current/setup/quick-start.md#部署示例应用)  
  - 在 `sleep` 部署中将副本数修改为 2：

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sleep
spec:
  replicas: 2
  selector:
    matchLabels:
      app: sleep
  template:
    metadata:
      labels:
        app: sleep
    spec:
      terminationGracePeriodSeconds: 0
      serviceAccountName: sleep
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
```

- 验证应用程序状态以确保服务应用程序由 Kmesh 管理：

```bash
# 检查 pod 状态
kubectl get pod -o wide | grep sleep
```

**预期输出：**

```bash
NAME                                READY   STATUS    RESTARTS   AGE     IP            NODE              NOMINATED NODE   READINESS GATES
sleep-78ff5975c6-phhll              1/1     Running   0          30h     10.244.2.22   ambient-worker    <none>           <none>
sleep-78ff5975c6-plh7r              1/1     Running   0          30h     10.244.1.46   ambient-worker2   <none>           <none>
```

```bash
# 验证 Kmesh 管理
kubectl describe pod httpbin-65975d4c6f-96kgw | grep Annotations
```

**预期输出：**

```text
Annotations:      kmesh.net/redirection: enabled
```

## 配置 ALLOW 授权策略

1. 为 `httpbin` 工作负载创建 "allow-by-srcip" 授权策略：

```bash
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-by-srcip
  namespace: default
spec:
  selector:
    matchLabels:
      app: httpbin
  action: ALLOW
  rules:
  - from:
    - source:
        ipBlocks:
        - 10.244.1.46/32
EOF
```

> 此策略仅允许来自指定 IP 地址 `10.244.1.46/32` 的请求，该 IP 地址对应于 pod `sleep-78ff5975c6-plh7r`。

2. 验证来自允许 IP 的请求成功：

```bash
kubectl exec sleep-78ff5975c6-plh7r -- curl http://httpbin:8000/headers
```

**预期输出：**

```json
{
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin:8000",
    "User-Agent": "curl/8.5.0"
  }
}
```

3. 验证来自其他 IP 的请求被拒绝：

```bash
kubectl exec sleep-78ff5975c6-phhll -- curl http://httpbin:8000/headers
```

**预期输出：**

```text
curl: (56) Recv failure: Connection reset by peer
```

4. 清理 `AuthorizationPolicy`：

```bash
kubectl delete AuthorizationPolicy allow-by-srcip -n default
```

## 配置 DENY 授权策略

1. 为 `httpbin` 工作负载创建 "deny-by-srcip" 授权策略：

```bash
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-by-srcip
  namespace: default
spec:
  selector:
    matchLabels:
      app: httpbin
  action: DENY
  rules:
  - from:
    - source:
        ipBlocks:
        - 10.244.1.46/32
EOF
```

> 此策略拒绝来自指定 IP 地址 `10.244.1.46/32` 的请求，该 IP 地址对应于 pod `sleep-78ff5975c6-plh7r`。

2. 验证来自被拒绝 IP 的请求被阻止：

```bash
kubectl exec sleep-78ff5975c6-plh7r -- curl "http://httpbin:8000/headers"
```

**预期输出：**

```text
curl: (56) Recv failure: Connection reset by peer
```

3. 验证来自其他 IP 的请求被允许：

```bash
kubectl exec sleep-78ff5975c6-phhll -- curl "http://httpbin:8000/headers"
```

**预期输出：**

```json
{
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin:8000",
    "User-Agent": "curl/8.5.0"
  }
}
```

4. 清理 `AuthorizationPolicy`：

```bash
kubectl delete AuthorizationPolicy deny-by-srcip -n default
```

## 清理

请参阅[清理指南](/i18n/zh/docusaurus-plugin-content-docs/current/setup/quick-start.md#清理)

## AuthorizationPolicy

### AuthorizationPolicy 字段

| 字段    | 类型     | 描述                                                                                                                                                                                                                                        | 必需 |
|---------|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| -------- |
| `rules` | `Rule[]` | 可选。用于匹配请求的规则列表。当至少一个规则匹配请求时，匹配发生。如果未设置，则永远不会发生匹配。如果 `action` 为 `ALLOW`，则这等同于为目标工作负载设置默认拒绝。 | 否       |

### Rule

`Rule` 匹配来自执行一系列操作的源列表的请求，需满足一系列条件。当至少一个源、一个操作和所有条件匹配请求时，匹配发生。空规则始终匹配。

| 字段   | 类型     | 描述                                                                           | 必需 |
|--------|----------|---------------------------------------------------------------------------------------| -------- |
| `from` | `From[]` | 可选。`from` 指定请求的源。如果未设置，则允许任何源。| 否       |
| `to`   | `To[]`   | 可选。`to` 指定请求的操作。如果未设置，则允许任何操作。 | 否       |

#### Rule.From

`From` 包含源列表。

| 字段     | 类型     | 描述                               | 必需 |
|----------|----------|-------------------------------------------| -------- |
| `source` | `Source` | `Source` 指定请求的源。 | 否       |

#### Rule.To

`To` 包含操作列表。

| 字段        | 类型        | 描述                                     | 必需 |
|-------------|-------------|-------------------------------------------------| -------- |
| `operation` | `Operation` | `Operation` 指定请求的操作。 | 否       |

### Source

`Source` 指定请求的源身份。源中的字段是 AND 关系。

例如，以下源匹配如果 `principal` 是 `admin` 或 `dev` 并且 `namespace` 是 `prod` 或 `test` 并且 `ip` 不是 `203.0.113.4`：

```yaml
principals: ["admin", "dev"]
namespaces: ["prod", "test"]
notIpBlocks: ["203.0.113.4"]
```

| 字段            | 类型       | 描述                                                                                                                                                                              | 必需 |
|-----------------|------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| -------- |
| `principals`    | `string[]` | 可选。从对等证书派生的对等身份列表。对等身份的格式为 `"<TRUST_DOMAIN>/ns/<NAMESPACE>/sa/<SERVICE_ACCOUNT>"`，例如 `"cluster.local/ns/default/sa/productpage"`。此字段需要启用 mTLS，并且与 `source.principal` 属性相同。如果未设置，则允许任何 `principal`。 | 否       |
| `notPrincipals` | `string[]` | 可选。对等身份的负匹配列表。                                                                                                                                   | 否       |
| `namespaces`    | `string[]` | 可选。从对等证书派生的命名空间列表。此字段需要启用 mTLS，并且与 `source.namespace` 属性相同。如果未设置，则允许任何命名空间。 | 否       |
| `notNamespaces` | `string[]` | 可选。命名空间的负匹配列表。                                                                                                                                        | 否       |
| `ipBlocks`      | `string[]` | 可选。IP 块列表，从 IP 数据包的源地址填充。支持单个 IP（例如 `203.0.113.4`）和 CIDR（例如 `203.0.113.0/24`）。这与 `source.ip` 属性相同。如果未设置，则允许任何 IP。 | 否       |
| `notIpBlocks`   | `string[]` | 可选。IP 块的负匹配列表。                                                                                                                                         | 否       |

### Operation

`Operation` 指定请求的操作。操作中的字段是 AND 关系。

| 字段       | 类型       | 描述                                                                               | 必需 |
|------------|------------|-------------------------------------------------------------------------------------------| -------- |
| `ports`    | `string[]` | 可选。连接中指定的端口列表。如果未设置，则允许任何端口。| 否       |
| `notPorts` | `string[]` | 可选。连接中指定的端口的负匹配列表。               | 否       |
