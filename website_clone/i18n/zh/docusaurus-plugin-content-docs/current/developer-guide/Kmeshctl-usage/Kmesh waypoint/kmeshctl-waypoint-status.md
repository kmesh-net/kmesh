---
title: kmeshctl waypoint status（航点状态）
sidebar_position: 6
---

显示所提供命名空间或默认命名空间（如果未提供）中航点的状态

```bash
kmeshctl waypoint status [flags]
```

### 示例

```bash
# 显示默认命名空间中航点的状态
kmeshctl waypoint status

# 显示特定命名空间中航点的状态
kmeshctl waypoint status --namespace default
```

### 选项

```bash
  -h, --help   status 命令的帮助信息
```

### 从父命令继承的选项

```bash
      --image string       航点的镜像
      --name string        航点的名称（默认为 "waypoint"）
  -n, --namespace string   Kubernetes 命名空间
```
