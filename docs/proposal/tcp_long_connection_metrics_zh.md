---
title: Kmesh TCP 长连接指标
authors:
- "@bitcoffeeiux"
reviewers:
- "@robot"
- TBD
approvers:
- "@robot"
- TBD
creation-date: 2024-01-15
---

# Kmesh TCP 长连接指标

## 摘要

本文档描述了 Kmesh 中 TCP 长连接指标的设计方案，用于监控和分析 TCP 长连接的性能和状态。

## 背景

TCP 长连接在微服务架构中广泛使用，需要有效的监控机制来保证其稳定性和性能。Kmesh 需要提供完善的长连接指标收集和分析能力。

## 目标

1. 收集 TCP 长连接指标
2. 提供实时监控能力
3. 支持性能分析
4. 实现告警机制

## 设计细节

### 架构设计

TCP 长连接监控系统包含以下组件：

1. 指标收集器
2. 数据处理器
3. 存储系统
4. 可视化界面
5. 告警系统

### 指标定义

#### 基础指标

```c
struct TcpMetrics {
    __u64 connection_duration;  // 连接持续时间
    __u64 bytes_sent;          // 发送字节数
    __u64 bytes_received;      // 接收字节数
    __u64 retransmissions;     // 重传次数
    __u64 rtt;                 // 往返时间
};
```

#### 高级指标

```c
struct TcpAdvancedMetrics {
    __u64 window_size;         // 窗口大小
    __u64 congestion_events;   // 拥塞事件
    __u64 keepalive_probes;   // 保活探测
    __u64 connection_resets;   // 连接重置
};
```

### 数据收集

```go
type MetricsCollector interface {
    CollectBasicMetrics() (*TcpMetrics, error)
    CollectAdvancedMetrics() (*TcpAdvancedMetrics, error)
    CollectCustomMetrics(types []string) (map[string]interface{}, error)
}
```

## 使用示例

### 查询指标

```bash
# 查询基础指标
curl http://localhost:8080/metrics/tcp/basic

# 查询高级指标
curl http://localhost:8080/metrics/tcp/advanced
```

### 配置告警

```yaml
alerts:
  - name: high_retransmission_rate
    condition: tcp_retransmissions > 100
    duration: 5m
    severity: warning
```

## 注意事项

1. 性能开销控制
2. 数据采样策略
3. 存储容量规划

## 未来工作

1. 支持更多指标类型
2. 优化数据采集效率
3. 增强分析能力

Upstream issue: https://github.com/kmesh-net/kmesh/issues/1211

### 摘要

目前，kmesh 在 TCP 连接关闭后提供访问日志，其中包含有关连接的更详细信息，例如发送的字节数、接收的字节数、丢包数、rtt 和重传数。

Kmesh 还提供工作负载和服务特定的指标，例如发送和接收的字节数、丢失的数据包、最小 rtt、pod 打开和关闭的总连接数。这些指标仅在连接关闭后更新。在本提案中，我们的目标是定期更新这些指标。

我们还旨在实现 TCP 长连接的访问日志和指标，开发一种连续监控和报告机制，以捕获长寿命 TCP 连接整个生命周期中的详细实时数据。定期报告访问日志，其中包含报告时间、连接建立时间、发送的字节数、接收的字节数、丢包数、rtt、重传数和状态等信息。还会定期报告长连接的指标，例如发送和接收的字节数、丢包数、重传数。

### 动机

可以尽早了解长连接的性能和健康状况，目前我们通过连接终止后提供的指标和访问日志获取连接的所有信息。

#### 目标

- 定期（5 秒）报告基于工作负载和服务的指标。

- 使用 ebpf 在长 TCP 连接的整个生命周期内持续收集详细的流量指标（例如，发送/接收的字节数、往返时间、数据包丢失、tcp 重传）。

- 以 5 秒的周期性时间报告指标和访问日志。我们选择 5 秒作为阈值时间，因为它允许有足够的时间来累积指标中有意义的更改。如果报告间隔太短，可能会因处理过多的更新而导致过多的开销。

- 从指标数据中生成包含有关连接信息的访问日志，并在长 TCP 连接的整个生命周期内持续生成。

- 指标和日志支持 open-telemetry 格式。

- 通过 kmesh 守护程序公开这些指标，以便 prometheus 可以抓取它。

- 单元测试和 E2E 测试。

#### 非目标

- 收集有关数据包内容的信息。

- 控制或修改 TCP 连接

- 收集 L7 指标

### 提案

TCP 连接信息将使用 eBPF cgroup_skb 钩子收集。RingBuffer map 用于定期将连接信息发送到用户空间。

### 设计细节

#### 收集指标

声明 ebpf cgroup_skb 钩子，当流量通过 cgroup 套接字时，将触发该钩子。

```
SEC("cgroup_skb/ingress")
int cgroup_skb_ingress_prog(struct __sk_buff *skb)
{
    if (skb->family != AF_INET && skb->family != AF_INET6)
        return SK_PASS;

    struct bpf_sock *sk = skb->sk;
    if (!sk)
        return SK_PASS;

    if (!is_managed_by_kmesh_skb(skb))
        return SK_PASS;
    observe_on_data(sk);
    return SK_PASS;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress_prog(struct __sk_buff *skb)
{
    if (skb->family != AF_INET && skb->family != AF_INET6)
        return SK_PASS;

    struct bpf_sock *sk = skb->sk;
    if (!sk)
        return SK_PASS;

    if (!is_managed_by_kmesh_skb(skb))
        return SK_PASS;
    observe_on_data(sk);
    return SK_PASS;
}

```
Observe_on_data 函数检查 lsat_report 之后经过的时间是否大于 5 秒。如果大于，则将 conn_info 报告给 ring_buffer 并更新 last_report_ns。

```
static inline void observe_on_data(struct bpf_sock *sk)
{
    struct bpf_tcp_sock *tcp_sock = NULL;
    struct sock_storage_data *storage = NULL;
    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        return;
    }
    __u64 now = bpf_ktime_get_ns();
    if ((storage->last_report_ns != 0) && (now - storage->last_report_ns > LONG_CONN_THRESHOLD_TIME)) {
        tcp_report(sk, tcp_sock, storage, BPF_TCP_ESTABLISHED);
    }
}
```

我们将更新 metric.go 的函数，以定期更新工作负载和服务指标，并且我们将为长 tcp 连接创建一个新指标。

![design](./pics/tcp_long_conn_design.png)

#### 公开长连接 prometheus 指标

我们将公开持续时间超过 5 秒的连接的指标。不公开短连接的指标，因为它可能导致大量指标，并且它们也不适合 prometheus 指标，因为 prometheus 本身具有 5 秒的抓取间隔，并且短寿命连接可能在抓取之间开始和结束，从而导致不完整或误导性的数据。通过仅关注较长寿命的连接，我们确保指标稳定、有意义，并且更好地与 Prometheus 的时间序列数据模型保持一致。

将来我们可以拥有另一个组件，该组件报告有关连接的实时信息，例如 cilium hubble。

公开的 Prometheus 指标

- `kmesh_tcp_connection_sent_bytes_total`：通过已建立的 TCP 连接发送的总字节数

- `kmesh_tcp_connection_received_bytes_total`：通过已建立的 TCP 连接接收的总字节数

- `kmesh_tcp_connection_packet_lost_total`：TCP 连接中传输期间丢失的数据包总数

- `kmesh_tcp_connection_retrans_total`：通过已建立的 TCP 连接重传的总数

以上指标具有以下标签

```
		"reporter"
		"start_time"
		"source_workload"
		"source_canonical_service"
		"source_canonical_revision"
		"source_workload_namespace"
		"source_principal"
		"source_app"
		"source_version"
		"source_cluster"
		"source_address"
		"destination_address"
		"destination_pod_address"
		"destination_pod_namespace"
		"destination_pod_name"
		"destination_service"
		"destination_service_namespace"
		"destination_service_name"
		"destination_workload"
		"destination_canonical_service"
		"destination_canonical_revision"
		"destination_workload_namespace"
		"destination_principal"
		"destination_app"
		"destination_version"
		"destination_cluster"
		"request_protocol"
		"response_flags"
		"connection_security_policy"
```

#### 用户故事（可选）

##### 故事 1
工作负载和服务 prometheus 指标会定期更新，并在连接关闭时更新。

##### 故事 2
一个新的 prometheus 指标用于定期更新的长 tcp 连接。

#### 注意事项/约束/警告（可选）

#### 风险和缓解措施

#### 测试计划

更新 bpf_test.go 以测试编写的 ebpf 代码。
同时更新 metric_test.go 以测试指标
### 备选方案

创建一个用户空间代理组件而不是 ebpf 来收集指标。
