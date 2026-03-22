---
sidebar_position: 3
title: XDP 中的 TCP 授权
---

## XDP 中的授权

之前，我们推出了[用户空间授权功能](/i18n/zh/docusaurus-plugin-content-docs/current/transpot-layer/tcp-authorization.md)，其中授权结果在用户空间进行验证。本文档解释了如何直接在 XDP 程序中启用授权。目前，基于 XDP 的授权仅支持基于端口和 IP 地址的验证。

### 如何启用基于 XDP 的授权

我们可以使用 `kmeshctl` 来启用基于 XDP 的授权：

```bash
./kmeshctl authz enable
```

修改 BPF 日志级别：

```bash
./kmeshctl log <$kmeshnode1> --set bpf:debug
```

## 配置拒绝授权策略

### 配置目标端口拒绝授权策略

为 Fortio 工作负载创建一个“deny-by-dstport”授权策略，拒绝发送到指定端口地址的请求。在此示例中，发送到端口 8080 的流量被拒绝：

```yaml
# deny-by-dstport.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-by-dstport
spec:
  selector:
    matchLabels:
      app: fortio-server
  action: DENY
  rules:
    - to:
        - operation:
            ports:
              - "8080"
```

应用策略：

```bash
kubectl apply -f deny-by-dstport.yaml
```

#### 测试策略

Fortio 流量返回的状态码确认发送到端口 8080 的流量已被拒绝：

```bash
kubectl exec -it fortio-client-deployment-6966bf9488-tpwpj -- fortio load -c 1 -n 1 -qps 0 -jitter=true 10.244.0.7:8080
```

预期输出：

```text
...
IP addresses distribution:
10.244.0.7:8080: 1
Code  -1 : 1 (100.0 %)
Response Header Sizes : count 1 avg 0 +/- 0 min 0 max 0 sum 0
Response Body/Total Sizes : count 1 avg 0 +/- 0 min 0 max 0 sum 0
All done 1 calls (plus 0 warmup) 3005.022 ms avg, 0.3 qps
```

Kmesh 记录的日志中也会打印特定信息：

```bash
kubectl logs -f kmesh-vlxhd -n kmesh-system
```

预期输出：

```log
...
time="2024-12-25T15:23:12+08:00" level=info msg="[AUTH] DEBUG: port 8080 in destination_ports, matched" subsys=ebpf
time="2024-12-25T15:23:12+08:00" level=info msg="[AUTH] DEBUG: rule matched, action: DENY" subsys=ebpf
```

### 配置源 IP 拒绝授权策略

创建策略以拒绝来自特定源 IP 的流量：

```yaml
# deny-by-srcip.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-by-srcip1
  namespace: default
spec:
  selector:
    matchLabels:
      app: fortio-server
  action: DENY
  rules:
    - from:
        - source:
            ipBlocks:
              - 10.244.1.36
```

应用策略：

```bash
kubectl apply -f deny-by-srcip.yaml
```

#### 测试策略

Fortio 流量返回的状态码确认从 IP 10.244.1.36 发送的流量已被拒绝：

```bash
# fortio-client-deployment-6966bf9488-m96qp 的 IP 地址是 10.244.1.36
kubectl exec -it fortio-client-deployment-6966bf9488-m96qp -- fortio load -c 1 -n 1 -qps 0 -jitter=true 10.244.0.36:8080
```

预期输出：

```text
...
IP addresses distribution:
10.244.0.36:8080: 1
Code  -1 : 1 (100.0 %)
Response Header Sizes : count 1 avg 0 +/- 0 min 0 max 0 sum 0
Response Body/Total Sizes : count 1 avg 0 +/- 0 min 0 max 0 sum 0
All done 1 calls (plus 0 warmup) 3005.563 ms avg, 0.3 qps
```

Kmesh 记录的日志中也会打印特定信息：

```bash
kubectl logs -f kmesh-vlxhd -n kmesh-system
```

预期输出：

```log
...
time="2024-12-26T15:05:26+08:00" level=info msg="[AUTH] DEBUG: rule matched, action: DENY" subsys=ebpf
time="2024-12-26T15:06:14+08:00" level=info msg="[AUTH] DEBUG: no ports configured, matching by default" subsys=ebpf
time="2024-12-26T15:06:14+08:00" level=info msg="[AUTH] DEBUG: IPv4 match srcip: Rule IP: af40124, Prefix Length: 32, Target IP: af40124\n" subsys=ebpf
```

### 配置目标 IP 拒绝授权策略

创建策略以拒绝发送到特定目标 IP 的流量：

```yaml
# deny-by-dstip.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-dstip
spec:
  selector:
    matchLabels:
      app: fortio-server
  action: DENY
  rules:
    - when:
        - key: destination.ip
          values: ["10.244.0.36"]
```

应用策略：

```bash
kubectl apply -f deny-by-dstip.yaml
```

#### 测试策略

Fortio 流量返回的状态码确认发送到 IP 10.244.0.36 的流量已被拒绝：

```bash
kubectl exec -it fortio-client-deployment-6966bf9488-m96qp -- fortio load -c 1 -n 1 -qps 0 -jitter=true 10.244.0.36:8080
```

预期输出：

```text
...
10.244.0.36:8080: 1
Code  -1 : 1 (100.0 %)
Response Header Sizes : count 1 avg 0 +/- 0 min 0 max 0 sum 0
Response Body/Total Sizes : count 1 avg 0 +/- 0 min 0 max 0 sum 0
All done 1 calls (plus 0 warmup) 3004.974 ms avg, 0.3 qps
```

Kmesh 记录的日志中也会打印特定信息：

```bash
kubectl logs -f kmesh-vlxhd -n kmesh-system
```

预期输出：

```log
...
time="2024-12-26T15:05:22+08:00" level=info msg="[AUTH] DEBUG: rule matched, action: DENY" subsys=ebpf
time="2024-12-26T15:05:26+08:00" level=info msg="[AUTH] DEBUG: no ports configured, matching by default" subsys=ebpf
time="2024-12-26T15:05:26+08:00" level=info msg="[AUTH] DEBUG: IPv4 match dstip: Rule IP: af40024, Prefix Length: 32, Target IP: af40024\n" subsys=ebpf
```
