---
title: Kmesh 架构
description: ""
sidebar_position: 1
---

![image](images/kmesh-arch.png)

## 架构概述

Kmesh 的软件架构由以下核心组件构成：

| 组件               | 描述                                                               |
| ------------------ | ------------------------------------------------------------------ |
| Kmesh-daemon       | 负责 eBPF 编排生命周期管理、xDS 协议集成、可观察性等功能的守护进程 |
| eBPF Orchestration | 使用 eBPF 实现的流量编排，包括动态路由、授权、负载均衡             |
| Waypoint           | 基于 istio 的 waypoint 适配 Kmesh 协议，负责 L7 流量管理           |

## 组件详情

### Kmesh-daemon

- eBPF 生命周期管理
- xDS 协议集成
- 可观察性和监控
- 配置管理

### eBPF Orchestration

- 动态路由实现
- 授权
- 负载均衡优化
- 流量加速

### Waypoint

- L7 流量管理
- Kmesh 协议适配
- 服务网格集成
- 流量策略执行
