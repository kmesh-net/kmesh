# 限流配置说明

Dashboard 通过 Istio **EnvoyFilter** 注入 `envoy.filters.network.local_ratelimit`，实现连接维度本地限流（Token Bucket），与 Kmesh 提案一致。

## 入口

**限流** 菜单 → **策略列表** / **配置限流**。

## 策略列表

- 展示集群中所有含 local_ratelimit 的 EnvoyFilter（可按命名空间筛选）。
- 表格字段：命名空间、名称、StatPrefix、最大令牌、每次填充、填充间隔(秒)、作用对象（workload 标签或「全部」）。
- 支持删除策略；列表即「已下发」的限流规则。

## 配置限流

- **命名空间**：EnvoyFilter 所在命名空间，通常与要限流的工作负载同命名空间。
- **EnvoyFilter 名称**：资源名称，如 `filter-local-ratelimit-svc`。
- **Stat 前缀**：可选，默认 `local_rate_limit`。
- **作用对象**：可选。从当前命名空间的服务列表中选择一个，用其名称作为 workload 的 `app` 标签，仅对该 workload 限流；不选则对该命名空间下所有匹配 listener（含 tcp_proxy）的 workload 生效。
- **Token Bucket**：
  - **max_tokens**：桶内最大令牌数（突发上限）。
  - **tokens_per_fill**：每次填充的令牌数。
  - **fill_interval（秒）**：填充间隔。例如 60 表示每 60 秒补充 tokens_per_fill 个令牌。
- 下发后会在「策略列表」中显示；可选在拓扑/指标中观察限流触发（如连接被拒绝、429 等）。

## 依赖

- 集群需已安装 Istio `networking.istio.io/v1alpha3` EnvoyFilter CRD。
- 当前实现为**连接维度**本地限流（TCP listener 插入 local_ratelimit），非 HTTP QPS 限流。
