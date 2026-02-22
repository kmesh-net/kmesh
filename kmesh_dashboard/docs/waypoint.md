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
