# Waypoint 使用指南

Dashboard 提供 Waypoint 的**列表与状态**、**安装**能力，与 `kmeshctl waypoint` 对齐。

## 列表与状态

- **Waypoint** 导航 → **列表与状态**：查看集群内所有 Waypoint（Gateway 资源，`gatewayClassName: istio-waypoint`）。
- 支持按「全部命名空间」或指定命名空间筛选。
- 表格展示：命名空间、名称、状态（已就绪/未就绪）、Revision、流量类型；支持展开查看 Conditions 详情。
- 支持单条删除。

## 安装

- **Waypoint** 导航 → **安装 Waypoint**：通过表单创建 Waypoint。
- **命名空间**：必填，默认 `default`。
- **Waypoint 名称**：必填，默认 `waypoint`；Workload 粒度时可填如 `reviews-v2-pod-waypoint`。
- **流量类型**：可选 `service`、`workload`、`all`、`none`，对应三粒度（Namespace/Service/Workload）。
- **为命名空间打标签**：勾选后为命名空间设置 `istio.io/use-waypoint`。
- **覆盖已有 Waypoint**、**等待就绪**、**Revision**、**Proxy 镜像**：可选。

创建后可在「列表与状态」中查看并等待 Programmed 就绪。

## 自定义 YAML

- **Waypoint** 导航 → **自定义 YAML**：通过 YAML 编辑器创建/更新 Waypoint（Gateway 资源）。
- 默认模板为 **Gateway** 资源（`kind: Gateway`），不是 Deployment。

### 重要说明：Gateway 与 Deployment 的关系

**您应用的是 Gateway，看到的 Deployment 由 Istio 自动生成。**

| 资源类型 | 谁创建 | 说明 |
|---------|--------|------|
| **Gateway** | 用户 / Dashboard | 您自定义的 YAML 会创建/更新 Gateway 资源 |
| **Deployment** | Istio mesh controller | 根据 Gateway 自动创建，配置由 Istio 控制 |

当您执行 `kubectl get deploy waypoint2 -o yaml` 时，看到的是 **Istio 控制器根据 Gateway 自动生成的 Deployment**，其 `ownerReferences` 指向 Gateway，`labels` 含 `gateway.istio.io/managed: istio.io-mesh-controller`。因此 Deployment 的 spec（如 containers、resources、volumes）与您在 Dashboard 中编辑的 Gateway YAML 不同，这是预期行为。

### 如何影响 Deployment 配置

- **Proxy 镜像**：在 Gateway 的 `metadata.annotations` 中添加 `sidecar.istio.io/proxyImage: <镜像>`。
- **高级自定义**（Istio 1.25+）：通过 `spec.infrastructure.parametersRef` 引用 ConfigMap，在 ConfigMap 的 `deployment` 键下定义 overlay（如 replicas、resources），详见 [Istio Gateway 自定义文档](https://istio.io/latest/docs/)。

### 查看您创建的 Gateway

```bash
kubectl get gateway waypoint2 -n default -o yaml
```

此处应能看到您在 Dashboard 中自定义的 Gateway 配置。
