# 指标大盘说明

Dashboard 从 **Prometheus** 拉取指标，在「指标」页统一展示 Kmesh L4 监控数据（直接获取累计值）。

## 入口

**指标** 菜单 → 服务网格指标。

## 数据来源与覆盖

- 后端通过环境变量 **PROMETHEUS_URL** 连接 Prometheus（例如 `export PROMETHEUS_URL=http://prometheus.kmesh-system:9090`）。未配置时页面提示「未配置 Prometheus」，不发起查询。
- 大盘直接展示 **累计值**（`sum(metric)`），无需持续流量即可看到非零数据：
  1. **Kmesh L4 工作负载指标**  
     - `kmesh_tcp_workload_connections_opened_total`、`kmesh_tcp_workload_connections_closed_total`  
     - `kmesh_tcp_workload_received_bytes_total`、`kmesh_tcp_workload_sent_bytes_total`  
     - `kmesh_tcp_workload_conntections_failed_total`（注意拼写）
  2. **Kmesh L4 服务指标**  
     - `kmesh_tcp_connections_opened_total`、`kmesh_tcp_connections_closed_total`  
     - `kmesh_tcp_received_bytes_total`、`kmesh_tcp_sent_bytes_total`  
     - `kmesh_tcp_conntections_failed_total`

## 页面能力

- **命名空间**：可选，空表示全部命名空间聚合。
- **刷新**：重新拉取当前指标。
- **展示分组**：
  - **工作负载指标**：连接打开/关闭/失败总数、收发字节总数
  - **服务指标**：连接打开/关闭/失败总数、收发字节总数
  - **Accesslog**：从 kmesh daemon pods 的容器日志中筛选 accesslog（直连 K8s，不依赖 Prometheus）

## Accesslog

Accesslog 通过 K8s Pod Logs API 直连获取，无需 Prometheus。需先执行 `kmeshctl monitoring --accesslog enable` 开启 accesslog 输出。

## 依赖

- **指标**：集群内需部署 Prometheus；Kmesh 启用遥测并上报上述 TCP 指标到 Prometheus。
- **Accesslog**：K8s 集群可访问；kmesh pods 位于 kmesh-system 命名空间。
