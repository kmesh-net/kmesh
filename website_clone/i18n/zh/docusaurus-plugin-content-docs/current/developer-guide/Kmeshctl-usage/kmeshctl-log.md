---
title: Kmeshctl Log
sidebar_position: 5
---

获取或设置 kmesh-daemon 的日志记录器级别

```bash
kmeshctl log [flags]
```

### 示例

```bash
# 将默认日志记录器的级别设置为 "debug"：
kmeshctl log <kmesh-daemon-pod> --set default:debug

# 获取所有日志记录器的名称
kmeshctl log <kmesh-daemon-pod>

# 获取默认日志记录器的级别：
kmeshctl log <kmesh-daemon-pod> default
```

### 选项

```bash
  -h, --help         help for log
      --set string   Set the logger level (e.g., default:debug)
```
