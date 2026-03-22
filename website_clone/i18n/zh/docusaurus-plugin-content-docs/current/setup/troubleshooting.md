---
title: 安装故障排除指南
sidebar_position: 4
---

## 常见安装问题

### 端口冲突

在部署Kmesh时，您可能会遇到端口冲突，尤其是默认使用的端口15006。

| 错误代码        | 描述                      | 影响                     | 解决方案                          |
| --------------- | ------------------------- | ------------------------ | --------------------------------- |
| ERR_PORT_IN_USE | 端口15006已被使用         | 阻止Kmesh启动           | 更改端口或释放现有端口            |
| MISSING_DEP     | 缺少libbpf依赖            | BPF功能不可用            | 安装libbpf ≥0.8                   |
| CNI_CONFLICT    | CNI插件冲突               | 网络设置失败             | 验证CNI配置                       |

## 详细解决方案

### 端口冲突解决

如果您遇到**ERR_PORT_IN_USE**，请按照以下步骤操作：

1. **诊断冲突**：

   ```shell
   # 检查什么正在使用端口15006
   sudo lsof -i :15006

   # 对于systemd服务
   sudo ss -lptn 'sport = :15006'
   ```

2. **解决选项**：

   a. 更改Kmesh端口：

   ```yaml
   # kmesh-config.yaml
   apiVersion: kmesh.net/v1
   kind: KmeshConfig
   metadata:
     name: kmesh-config
     namespace: kmesh-system
   spec:
     port: 15007
     logLevel: info
     enableMetrics: true
   ```

   b. 释放现有端口：

   ```shell
   # 识别并停止冲突进程
   sudo fuser -k 15006/tcp
   ```

### 依赖管理

#### 安装libbpf

BPF功能所需：

```bash
# Ubuntu/Debian系统
sudo apt-get update
sudo apt-get install -y \
    libbpf-dev \
    linux-headers-$(uname -r)

# 验证安装
dpkg -l | grep libbpf

# CentOS/RHEL系统
sudo yum install -y libbpf-devel kernel-devel
```

## 运行时验证

### 系统要求检查

```shell
# 内核版本检查
uname -r  # 应≥5.10.0以获得完整功能

# BPF验证
sudo bpftool prog list

# 资源限制
ulimit -n  # 应≥65535
```

### Pod管理

验证Kmesh集成：

```shell
# 检查pod注解
kubectl get pod <pod-name> -o jsonpath='{.metadata.annotations}' | jq

# 启用Kmesh管理
kubectl label namespace default istio.io/dataplane-mode=Kmesh --overwrite

# 验证Kmesh状态
kubectl -n kmesh-system get pods -l app=kmesh
```

### 日志记录和调试

#### 增强日志记录

```shell
# 启用调试日志
kmeshctl accesslog <kmesh-pod-name> --set default:debug

# 监控BPF事件（内核≥5.10.0）
kubectl exec -n kmesh-system <kmesh-pod> -- kmesh-daemon log --set bpf:debug

# 收集所有日志
kubectl logs -n kmesh-system -l app=kmesh --all-containers --tail=1000 > kmesh-debug.log
```

## 清理程序

### 清理

移除Kmesh及其配置：

```shell
# 使用Helm
helm uninstall kmesh -n kmesh-system

# 使用kubectl
kubectl delete namespace kmesh-system
kubectl delete -f kmesh-config.yaml

# 清理CNI配置
sudo rm -f /etc/cni/net.d/kmesh-cni*
```

### 配置重置

重置为默认设置：

```shell
# 移除命名空间标签
kubectl label namespace default istio.io/dataplane-mode-

# 重置CNI
kubectl -n kmesh-system delete pod -l app=kmesh-cni
```

## 健康验证

### 系统健康检查

```shell
# 组件状态
kubectl get componentstatuses

# 事件监控
kubectl get events -n kmesh-system --sort-by='.lastTimestamp'

# 资源使用情况
kubectl top pod -n kmesh-system
```

## 其他资源
<!-- for now there no link added -->
- [Kmesh Architecture Guide](/i18n/zh/docusaurus-plugin-content-docs/current/architecture/architecture.md)
- [Performance Tuning](/i18n/zh/docusaurus-plugin-content-docs/current/performance/performance.md)
- [Community Support](/i18n/zh/docusaurus-plugin-content-docs/current/community/contribute.md)

对于更复杂的问题，请参考我们的[GitHub Issues](https://github.com/kmesh-net/kmesh/issues)或加入我们的社区频道。

```text
This translation ensures that:
- The Markdown structure (headers, code blocks, tables) remains intact.
- Descriptive text is translated into natural and accurate Chinese.
- Technical commands and configurations are preserved in their original English form, with comments translated for better understanding.
- The document is ready to be copied and used directly in a Markdown editor.
```
