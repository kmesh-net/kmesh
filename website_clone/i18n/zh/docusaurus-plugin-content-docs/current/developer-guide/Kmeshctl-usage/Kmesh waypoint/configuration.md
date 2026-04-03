---
title: 配置
sidebar_position: 1
---

管理 waypoint 配置

### 概要

一组用于管理 waypoint 配置的命令

```bash
kmeshctl waypoint [flags]
```

### 示例

```bash
  # 将 waypoint 应用到当前命名空间
  kmeshctl waypoint apply

  # 以 yaml 格式生成 waypoint
  kmeshctl waypoint generate --namespace default

  # 列出特定命名空间中的所有 waypoint
  kmeshctl waypoint list --namespace default
```

### 选项

```bash
  -h, --help               waypoint 的帮助信息
      --image string       waypoint 的镜像
      --name string        waypoint 的名称（默认为 "waypoint"）
  -n, --namespace string   Kubernetes 命名空间
```
