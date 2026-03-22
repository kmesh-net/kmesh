---
title: kmeshctl 航点删除
sidebar_position: 3
---

从集群中删除 waypoint 配置

```bash
kmeshctl waypoint delete [flags]
```

### 示例

```bash
# 从默认命名空间中删除 waypoint
kmeshctl waypoint delete

# 按名称删除 waypoint，可以通过 kmeshctl waypoint list 获取名称
kmeshctl waypoint delete waypoint-name --namespace default

# 按名称删除多个 waypoint
kmeshctl waypoint delete waypoint-name1 waypoint-name2 --namespace default

# 删除特定命名空间中的所有 waypoint
kmeshctl waypoint delete --all --namespace default
```

### 选项

```bash
      --all    删除命名空间中的所有 waypoint
  -h, --help   delete 的帮助
```

### 从父命令继承的选项

```bash
      --image string       waypoint 的镜像
      --name string        waypoint 的名称（默认为 "waypoint"）
  -n, --namespace string   Kubernetes 命名空间
```
