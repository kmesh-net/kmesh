# 指标大盘说明

Dashboard 从 **Prometheus** 拉取指标，在「指标」页统一展示服务网格关键性能指标：**Throughput（吞吐）**、**Error rates（错误率）**、**Latency（延迟）**，满足 “Integrated metrics dashboard showing key service mesh performance indicators (latency, error rates, throughput)” 要求。

## 入口

**指标** 菜单 → 服务网格指标。

## 数据来源与覆盖

- 后端通过环境变量 **PROMETHEUS_URL** 连接 Prometheus（例如 `http://prometheus.kmesh-system.svc:9090`）。未配置时页面提示「未配置 Prometheus」，不发起查询。
- 大盘同时查询两类数据源，无数据时对应图表为空，不影响其他图表：
  1. **Kmesh L4 TCP 指标**（服务维度，与 `pkg/controller/telemetry` 一致）  
     - 连接建立/关闭速率、发送/接收字节率、连接失败速率  
     - 指标名：`kmesh_tcp_connections_opened_total`、`kmesh_tcp_connections_closed_total`、`kmesh_tcp_sent_bytes_total`、`kmesh_tcp_received_bytes_total`、`kmesh_tcp_conntections_failed_total`（注意拼写为 conntections）
  2. **Istio L7 指标**（可选，集群有 Istio/Envoy 上报时才有数据）  
     - 请求量 RPS、5xx 错误率、请求延迟 P50/P95/P99  
     - 指标名：`istio_requests_total`、`istio_request_duration_milliseconds_bucket`，`reporter="destination"`，可按 `destination_service_namespace` 筛选。

## 页面能力

- **时间范围**：最近 5 分钟、15 分钟、1 小时。
- **命名空间**：可选，空表示全部命名空间聚合（L4 与 L7 查询均使用该筛选）。
- **刷新**：重新请求当前时间范围与命名空间。
- **图表分组**：
  - **Throughput / 吞吐**：RPS (L7)、连接建立/关闭速率 (L4)、发送/接收字节率 (L4)
  - **Error rates / 错误率**：5xx 错误率 (L7)、连接失败速率 (L4)
  - **Latency / 延迟 (L7)**：P50、P95、P99（毫秒）

## 依赖

- 集群内需部署 Prometheus。
- **L4 指标**：Kmesh 启用遥测并上报上述 TCP 指标到 Prometheus。
- **L7 指标**：集群内需有 Istio 或兼容的 Envoy 指标（`istio_requests_total`、`istio_request_duration_milliseconds_bucket`）被 Prometheus 抓取；无 L7 时延迟与 5xx/RPS 图表可能为空。
