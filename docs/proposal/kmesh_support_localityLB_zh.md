---
title: Kmesh 的本地性负载均衡
authors:
- "@derekwin"
reviewers:
- "@kwb0523"
- "@hzxuzhonghu"
approvers:
- "@robot"
- TBD

creation-date: 2024-06-07
---

# Kmesh 的本地性负载均衡

## 摘要

为 Kmesh 工作负载模式添加本地性负载均衡。

## 背景

目前，Kmesh 不支持本地性感知负载均衡。本地性负载均衡通过将流量导向最近的服务实例来优化分布式系统中的性能和可靠性。这种方法减少了延迟，提高了可用性，并降低了与跨区域数据传输相关的成本。它还确保了符合数据主权法规，并通过提供更快、更可靠的服务响应来改善整体用户体验。

## 目标

本提案的目的是为 kmesh 工作负载模式添加本地性感知负载均衡能力，对应于 istio ambient mesh 中的本地性负载均衡。

## 提案

本地性负载均衡模式包括：本地性故障转移和本地性严格模式。

### 本地性故障转移模式

当请求访问服务时，控制平面将对流量的源 pod 的本地性信息与服务背后所有健康后端的本地性进行分层匹配。匹配度更高的 Pod 表示它们在地理位置上更接近，流量将优先路由到匹配度更高的 Pod。

### 本地性严格模式

在本地性严格模式下，LB（负载均衡）算法将仅选择与 routingPreference 完全匹配的后端。这意味着在这种模式下，负载均衡器会强制执行严格的策略，仅根据与指定本地性偏好的完全匹配将流量路由到后端，从而确保请求由满足与其位置或其他属性相关的特定标准的服务器处理。

## 设计细节

### 实现细节

1. 在 BPF 侧的 `service_manager` 中实现新的负载均衡处理逻辑：`lb_locality_failover_handle`
2. 向 BPF 侧的数据结构添加必要信息：
   - map `service_value` 存储负载均衡策略 `lb_policy` 和数组 `prio_endpoint_count[PRIO_COUNT]`
   - map `endpoint_key` 存储当前端点的优先级 `prio`
3. 在用户侧添加 `locality_cache` 模块，用于存储本地性感知信息和优先级计算逻辑
4. 更新用户侧的 `ServiceValue` 和 `EndpointKey` map

### 数据结构

#### workload.h

```c
typedef struct {
    __u32 prio_endpoint_count[PRIO_COUNT];
    __u32 lb_policy;
    __u32 service_port[MAX_PORT_COUNT];
    __u32 target_port[MAX_PORT_COUNT];
    struct ip_addr wp_addr;
    __u32 waypoint_port;
} service_value;

typedef struct {
    __u32 service_id;
    __u32 prio;
    __u32 backend_index;
} endpoint_key;
```

#### workload_common.h

```c
typedef enum {
    LB_POLICY_RANDOM = 0,
    LB_POLICY_STRICT = 1,
    LB_POLICY_FAILOVER = 2,
} lb_policy_t;
```

### 控制流

![locality_lb](pics/locality_lb.svg)

