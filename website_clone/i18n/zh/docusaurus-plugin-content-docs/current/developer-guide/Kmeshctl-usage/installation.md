---
title: Kmeshctl 安装
sidebar_position: 1
---

## 安装

### 1. 从发布二进制文件安装

预构建的二进制文件可在我们的[发布页面](https://github.com/kmesh-net/kmesh/releases)上获取。

```bash
# 适用于 AMD64 / x86_64
[ $(uname -m) = x86_64 ] && curl -Lo ./kmeshctl https://github.com/kmesh-net/kmesh/releases/download/v1.0.0/kmeshctl-linux-amd64
# 适用于 ARM64
[ $(uname -m) = aarch64 ] && curl -Lo ./kmeshctl https://github.com/kmesh-net/kmesh/releases/download/v1.0.0/kmeshctl-linux-arm64
chmod +x ./kmeshctl
sudo mv ./kmeshctl /usr/local/bin/kmeshctl
```

### 2. 从源代码构建

Kmeshctl 仍在快速发展中。如果您想尝试最新功能，可以直接从源代码构建并安装。

```bash
# 从 GitHub 克隆源代码
git clone https://github.com/kmesh-net/kmesh.git

# 构建并安装 kmeshctl
cd kmesh/
make kmeshctl
chmod +x ./kmeshctl
sudo mv ./kmeshctl /usr/local/bin/kmeshctl
```

## 命令参考

### kmeshctl accesslog

启用或禁用 Kmesh 的访问日志

```bash
kmeshctl accesslog [flags]
```

**示例**

```bash
# 启用 Kmesh 的访问日志：
kmeshctl accesslog <kmesh-daemon-pod> enable

# 禁用 Kmesh 的访问日志：
kmeshctl accesslog <kmesh-daemon-pod> disable
```

**选项**

```bash
  -h, --help   accesslog 命令的帮助信息
```
