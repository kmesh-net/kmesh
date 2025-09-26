---
title: Kmesh 本地限流
authors:
- "@luoyunhe"
reviewers:
- "@robot"
- TBD
approvers:
- "@robot"
- TBD
creation-date: 2024-01-15
---

# Kmesh 本地限流

## 摘要

本文档描述了 Kmesh 的本地限流功能设计和实现。

## 背景

在微服务架构中，限流是保护服务不被过载的重要机制。本地限流作为一种基础的限流方式，可以有效地控制单个服务实例的请求量。

## 目标

1. 实现基于令牌桶算法的本地限流
2. 支持多种限流粒度（全局、路由级别）
3. 提供灵活的限流配置接口

## 设计细节

### 架构设计

本地限流模块主要包含以下组件：

1. 限流配置管理器
2. 令牌桶实现
3. 限流决策器

### 实现细节

#### 限流配置结构

```c
struct RateLimit {
    __u32 tokens_per_fill;    // 每次填充的令牌数
    __u32 fill_interval;      // 填充间隔（毫秒）
    __u32 max_tokens;         // 最大令牌数
    __u32 tokens;             // 当前令牌数
    __u64 last_fill_time;     // 上次填充时间
};
```

#### 令牌桶实现

```c
static __always_inline bool consume_token(struct RateLimit *rl)
{
    __u64 now = bpf_ktime_get_ns() / 1000000;  // 转换为毫秒
    __u64 elapsed = now - rl->last_fill_time;
    
    if (elapsed >= rl->fill_interval) {
        __u32 fills = elapsed / rl->fill_interval;
        __u32 new_tokens = fills * rl->tokens_per_fill;
        
        rl->tokens = min(rl->max_tokens, rl->tokens + new_tokens);
        rl->last_fill_time = now;
    }
    
    if (rl->tokens > 0) {
        rl->tokens--;
        return true;
    }
    
    return false;
}
```

### 配置示例

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: local-ratelimit
spec:
  configPatches:
    - applyTo: HTTP_FILTER
      match:
        context: SIDECAR_INBOUND
      patch:
        operation: INSERT_BEFORE
        value:
          name: envoy.filters.http.local_ratelimit
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
            stat_prefix: http_local_rate_limiter
            token_bucket:
              max_tokens: 10000
              tokens_per_fill: 1000
              fill_interval: 1s
```

## 使用说明

1. 配置限流规则
2. 监控限流指标
3. 调整限流参数

## 注意事项

1. 合理设置限流阈值
2. 监控限流效果
3. 定期评估和调整限流策略

## 未来工作

1. 支持更多限流算法
2. 添加动态配置能力
3. 增强监控和告警功能

