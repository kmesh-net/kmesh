# ADS 模式部署与使用指南

ADS (Aggregated Discovery Service) 模式，即 **Kernel-Native 模式**，通过 eBPF 直接在内核中实现 L4 和简单的 L7 (HTTP) 流量控制。在此模式下，Kmesh 作为一个标准的 xDS 客户端，通过 ADS 协议从控制面（如 Istiod）订阅 CDS、EDS、LDS 和 RDS 资源。

## 前置条件

- 已运行的 Kubernetes 集群（v1.26+）。

- 已安装并运行在 `istio-system` 命名空间的 Istio 控制面 (Istiod)。

- Linux 内核版本 5.10+（支持 ADS 模式下的 L4/L7 功能）。

## 部署指南

### 1. 配置 Kmesh 为 ADS 模式

默认情况下，Daemonset 使用 `dual-engine` 模式。要启用 ADS 模式，请修改 `deploy/yaml/kmesh.yaml` 中的启动参数：

```yaml
# deploy/yaml/kmesh.yaml
args: [ "./start_kmesh.sh --mode=kernel-native --enable-bypass=false" ]

```

### 2. 部署 Kmesh Daemonset

将部署清单应用到集群：

```bash
kubectl apply -f deploy/yaml/kmesh.yaml

```

等待所有 Kmesh pod 运行就绪：

```bash
kubectl get pods -n kmesh-system

```

### 3. 为命名空间启用 Kmesh

为目标命名空间添加标签，以通过 Kmesh 管理其 Pod 流量：

```bash
kubectl label namespace <your-namespace> istio.io/dataplane-mode=Kmesh

```

该命名空间中新创建的 Pod 将被 Kmesh 拦截并管理。

## 验证

查看 Kmesh pod 日志，确认 xDS 订阅成功：

```bash
kubectl logs -n kmesh-system <kmesh-pod-name>

```

通过查询 Kmesh 管理控制台，验证 BPF map 是否已成功填充且配置已生效。您可以将 Kmesh pod 的状态端口（15200）端口转发到本地进行访问：

```bash
# 为 Kmesh pod 状态端口设置端口转发
kubectl port-forward -n kmesh-system <kmesh-pod-name> 15200:15200

# 在另一个终端中查询 BPF 配置转储
curl http://localhost:15200/debug/config_dump/bpf/kernel-native

```

## 使用示例

### 1. HTTP 路由

您可以使用标准的 Istio `VirtualService` 根据主机或路径路由流量：

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: reviews-route
spec:
  hosts:
  - reviews
  http:
  - match:
    - uri:
        prefix: /v2
    route:
    - destination:
        host: reviews
        subset: v2
  - route:
    - destination:
        host: reviews
        subset: v1

```

### 2. 负载均衡

使用 `DestinationRule` 配置负载均衡：

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: reviews-lb
spec:
  host: reviews
  trafficPolicy:
    loadBalancer:
      simple: LEAST_CONN

```

### 3. 灰度（金丝雀）发布

通过权重分配流量：

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: reviews-canary
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

```

### 4. TCP 灰度

同时也支持 L4 流量分配：

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: tcp-canary
spec:
  hosts:
  - tcp-echo
  tcp:
  - route:
    - destination:
        host: tcp-echo
        subset: v1
      weight: 80
    - destination:
        host: tcp-echo
        subset: v2
      weight: 20

```
