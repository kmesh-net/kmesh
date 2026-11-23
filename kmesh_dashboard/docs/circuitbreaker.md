# 熔断配置说明

Dashboard 通过 Istio **DestinationRule** 的 `trafficPolicy.connectionPool` 配置熔断与连接池，与 Envoy/Kmesh 提案字段对齐。

## 入口

**熔断** 菜单 → **策略列表** / **配置熔断**。

## 策略列表

- 展示集群中所有带 `connectionPool` 的 DestinationRule（可按命名空间筛选）。
- 表格字段：命名空间、名称、目标 Host、最大连接数、最大待处理请求、最大请求数、最大重试、连接超时、每连接最大请求数。
- 支持删除策略。

## 配置熔断

- **预设模板**：保守（低阈值）、标准、激进（高阈值），选择后自动填充下方数值。
- **自定义**：不选模板时手动填写各阈值。
- **必填**：命名空间、DestinationRule 名称、目标 Host（服务名，如 `reviews`、`httpbin.default.svc.cluster.local`）。
- **可选阈值**（与 proposal 对齐）：
  - **maxConnections**：TCP 最大连接数
  - **http1MaxPendingRequests**：最大待处理 HTTP 请求
  - **http2MaxRequests**：HTTP/2 最大请求数
  - **maxRetries**：最大重试次数
  - **connectTimeout**：连接超时（表单为 ms）
  - **maxRequestsPerConnection**：每连接最大请求数
- 前端对数字做范围校验；应用后写入集群 DestinationRule，已存在则更新。
- 集群需已安装 Istio `networking.istio.io/v1beta1` DestinationRule CRD，否则接口会报错。
