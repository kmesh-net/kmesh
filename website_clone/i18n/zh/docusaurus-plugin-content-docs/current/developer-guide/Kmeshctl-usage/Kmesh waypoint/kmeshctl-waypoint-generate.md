---
title: kmeshctl waypoint generate
sidebar_position: 4
---

以 YAML 格式生成 waypoint 配置

```bash
kmeshctl waypoint generate [flags]
```

### 示例

```bash
# 以 yaml 格式生成 waypoint
kmeshctl waypoint generate --namespace default

# 生成一个 waypoint，可以处理默认命名空间中服务的流量
kmeshctl waypoint generate --for service -n default
```

### 选项

```bash
      --for string        指定 waypoint 的流量类型 [all none service workload]
  -h, --help              generate 的帮助
  -r, --revision string   标记 waypoint 的修订版本
```

### 从父命令继承的选项

```bash
      --image string       waypoint 的镜像
      --name string        waypoint 的名称（默认为 "waypoint"）
  -n, --namespace string   Kubernetes 命名空间
```
