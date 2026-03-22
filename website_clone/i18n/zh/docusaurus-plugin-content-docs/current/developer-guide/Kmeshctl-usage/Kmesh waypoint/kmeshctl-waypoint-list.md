---
title: kmeshctl waypoint list（列出航点）
sidebar_position: 5
---

列出集群中托管的航点配置

```bash
kmeshctl waypoint list [flags]
```

### 示例

```bash
# 列出特定命名空间中的所有航点
kmeshctl waypoint list --namespace default

# 列出集群中的所有航点
kmeshctl waypoint list -A
```

### 选项

```bash
  -A, --all-namespaces   列出所有命名空间中的所有航点
  -h, --help             list 命令的帮助信息
```

### 从父命令继承的选项

```bash
      --image string       航点的镜像
      --name string        航点的名称（默认为 "waypoint"）
  -n, --namespace string   Kubernetes 命名空间
```
