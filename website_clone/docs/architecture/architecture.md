---
title: Kmesh Architecture
description: ""
sidebar_position: 1
---

![image](images/kmesh-arch.png)

## Architecture Overview

The software architecture of Kmesh consists of the following core components:

| Component          | Description                                                                                                                      |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| Kmesh-daemon       | The daemon responsible for eBPF Orchestration lifecycle management, xDS protocol integration, observability, and other functions |
| eBPF Orchestration | The traffic orchestration implemented with eBPF, including dynamic routing, authorization, load balancing                        |
| Waypoint           | Based on istio's waypoint to adapt to Kmesh protocols, responsible for L7 traffic management                                     |

## Component Details

### Kmesh-daemon

- eBPF lifecycle management
- xDS protocol integration
- Observability and monitoring
- Configuration management

### eBPF Orchestration

- Dynamic routing implementation
- Authorization
- Load balancing optimization
- Traffic acceleration

### Waypoint

- L7 traffic management
- Protocol adaptation for Kmesh
- Service mesh integration
- Traffic policy enforcement
