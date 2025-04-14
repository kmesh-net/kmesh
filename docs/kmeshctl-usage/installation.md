---
title: Kmeshctl Installation
sidebar_position: 1
---

## Installation

### 1. From Release Binaries

Pre-built binaries are available on our [releases page](https://github.com/kmesh-net/kmesh/releases).

```bash
# For AMD64 / x86_64
[ $(uname -m) = x86_64 ] && curl -Lo ./kmeshctl https://github.com/kmesh-net/kmesh/releases/download/v1.0.0/kmeshctl-linux-amd64
# For ARM64
[ $(uname -m) = aarch64 ] && curl -Lo ./kmeshctl https://github.com/kmesh-net/kmesh/releases/download/v1.0.0/kmeshctl-linux-arm64
chmod +x ./kmeshctl
sudo mv ./kmeshctl /usr/local/bin/kmeshctl
```

### 2. From Source

Kmeshctl is still in rapid development. If you want to try the latest features, you can directly build and install it from source.

```bash
# Clone source code from github
git clone https://github.com/kmesh-net/kmesh.git

# Build and install kmeshctl
cd kmesh/
make kmeshctl
chmod +x ./kmeshctl
sudo mv ./kmeshctl /usr/local/bin/kmeshctl
```

## Commands Reference

### kmeshctl accesslog

Enable or disable Kmesh's accesslog

```bash
kmeshctl accesslog [flags]
```

**Examples**
```bash
# Enable Kmesh's accesslog:
kmeshctl accesslog <kmesh-daemon-pod> enable

# Disable Kmesh's accesslog:
kmeshctl accesslog <kmesh-daemon-pod> disable
```

**Options**
```
  -h, --help   help for accesslog
```
