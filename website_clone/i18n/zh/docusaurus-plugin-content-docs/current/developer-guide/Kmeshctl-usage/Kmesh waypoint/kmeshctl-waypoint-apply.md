---
title: kmeshctl waypoint apply
sidebar_position: 2
---

将 waypoint 配置应用到集群

```bash
kmeshctl waypoint apply [flags]
```

### 示例

```bash
# 将 waypoint 应用到当前命名空间
kmeshctl waypoint apply

# 将 waypoint 应用到特定命名空间并等待其准备就绪
kmeshctl waypoint apply --namespace default --wait

# 将 waypoint 应用到特定 pod
kmeshctl waypoint apply -n default --name reviews-v2-pod-waypoint --for workload
```

### 选项

```bash
      --enroll-namespace   如果设置，命名空间将使用 waypoint 名称进行标记
      --for string         为 waypoint 指定流量类型 [all none service workload]
  -h, --help               apply 命令的帮助信息
      --overwrite          覆盖命名空间中已使用的现有 waypoint
  -r, --revision string    用于标记 waypoint 的修订版本
  -w, --wait               等待 waypoint 准备就绪
```

### 从父命令继承的选项

```bash
      --image string       waypoint 的镜像
      --name string        waypoint 的名称（默认为 "waypoint"）
  -n, --namespace string   Kubernetes 命名空间
```
