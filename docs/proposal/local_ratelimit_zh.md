---
title: 本地速率限制
authors:
- "yuanqijing"
reviewers:
- "@tacslon"
- "@hzxuzhonghu"
- "@nlwcy"
- TBD
approvers:
- "@robot"
- TBD

creation-date: 2024-09-19

---

## 支持本地速率限制

### 摘要
Envoy 支持本地速率限制，但 Kmesh 目前不支持。本提案旨在向 Kmesh 添加本地速率限制，重点是每个连接的速率限制。

### 动机
当许多下游客户端向一个上游服务器发送请求时，为每个客户端配置适当的熔断策略具有挑战性。熔断不能有效地处理突发连接。在 Istio 中，EnvoyFilters 在过滤器链中处理连接之前对其应用速率限制，从而提供更好的控制。

Envoy 支持以下速率限制机制：
* **网络速率限制**: Envoy 检查每个新连接的速率限制服务，使用配置的域来限制每秒的连接数。
* **HTTP 速率限制**: Envoy 检查每个 HTTP 请求的速率限制服务，基于路由设置，限制对上游和集群间的请求。
* **基于配额的速率限制**: 强制执行资源使用随时间的配额。

Envoy 支持两种速率限制部署模式：
* **全局速率限制**: 当客户端发起新的连接请求时，Envoy 触发监听器中的速率限制过滤器。然后，该过滤器与外部全局速率限制服务通信，以确定是否允许该连接。
* **本地速率限制**: Envoy 直接在数据平面中处理速率限制逻辑，无需外部速率限制服务。

由于 Kmesh 是基于 eBPF 的数据平面，不支持外部服务，因此实现全局速率限制是不可行的。因此，本提案侧重于添加本地速率限制，特别是每个连接的速率限制，以处理突发连接并有效管理负载。

**目标**:
* 向 Kmesh 添加本地速率限制以支持每个连接的速率限制。

**非目标**:
* 向 Kmesh 添加全局速率限制。
* 实现 HTTP 速率限制或基于配额的速率限制。

### 设计细节
#### 在 Istio 中的配置
要在 Envoy 中启用本地速率限制，请使用 EnvoyFilter 将 `local_ratelimit` 过滤器插入到监听器的过滤器链中。以下是一个 YAML 配置示例：
```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: filter-local-ratelimit-svc
  namespace: istio-system
spec:
  configPatches:
    - applyTo: NETWORK_FILTER
      match:
        listener:
          filterChain:
            filter:
              name: envoy.filters.network.tcp_proxy
      patch:
        operation: INSERT_BEFORE
        value:
          name: envoy.filters.network.local_ratelimit
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.local_ratelimit.v3.LocalRateLimit
            stat_prefix: local_rate_limit
            token_bucket:
              max_tokens: 4
              tokens_per_fill: 4
              fill_interval: 60s
```

上面的配置将 local_ratelimit 过滤器插入到监听器的过滤器链中的 tcp_proxy 过滤器之前。

在 xds 中，local_ratelimit 过滤器定义如下：
```json
{
  "stat_prefix": "local_rate_limit",
  "token_bucket": {
    "max_tokens": 4,
    "tokens_per_fill": 4,
    "fill_interval": "60s"
  }
}
```
token_bucket 设置定义了如何强制执行速率限制。`max_tokens` 指定 bucket 可以容纳的最大令牌数，设置突发容量。`tokens_per_fill` 确定在每个填充间隔添加到 bucket 的令牌数，`fill_interval` 定义了补充令牌的时间间隔。在上面的示例中，bucket 最多可以容纳 4 个令牌，每 60 秒添加 4 个令牌。此配置允许每分钟最多 4 个新连接。

#### 本地速率限制逻辑
如下图所示，Kmesh 中的每个连接的速率限制过程如下：
1. **连接发起**: 客户端发起新的连接请求。
2. **监听器调用**: 连接请求到达监听器的 hook 点。在执行过滤器链之前，应用速率限制逻辑。
3. **速率限制决策**: 速率限制器记录历史连接数（存储在 ebpf 哈希映射中），并将其与 `token_bucket` 配置进行比较。基于此比较，它确定是允许还是拒绝新连接。

![本地速率限制](./pics/local_ratelimit.svg)

在 filter_chain_manager 中，我们通过调用一个函数来集成速率限制逻辑，该函数基于连接尝试检查和更新令牌桶：
1. **过滤器匹配**: 该函数首先验证 local_ratelimit 过滤器是否存在于过滤器链中。如果不存在，则允许连接继续进行而不进行速率限制。
2. **配置检索**: 它从匹配的过滤器中检索 rate_limit 和 token_bucket 配置。
3. **速率限制决策**: 速率限制器使用客户端的地址作为密钥来访问相应的令牌桶。根据自上次令牌补充以来经过的时间，将令牌添加到 bucket 中，直到达到最大容量。如果令牌可用，则消耗一个令牌以允许连接；否则，连接将被拒绝。

速率限制逻辑遵循令牌桶算法来管理连接速率：
1. **初始化**: 当遇到新的客户端地址时，将使用最大令牌数 (max_tokens) 初始化令牌桶。
2. **令牌补充**: 令牌会定期添加到 bucket 中，间隔由 fill_interval 定义，确保 bucket 不超过 max_tokens。
3. **连接处理**: 如果令牌可用，则消耗一个令牌，并允许连接。如果没有令牌可用，则连接将被拒绝。

![令牌桶](./pics/token_bucket_algorithm.png)
