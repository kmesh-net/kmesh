---
title: Kmesh 可观测性提案
authors:
- "@LiZhencheng9527" # 此处填写作者的 GitHub 账号
reviewers:
- ""
- TBD
approvers:
- ""
- TBD

creation-date: 2024-05-16

---

## Kmesh 可观测性提案

<!--
这是你的 KEP 的标题。保持简短、简单和描述性。一个好的标题可以帮助沟通 KEP 的内容，应该被视为任何审查的一部分。
-->

### 摘要

<!--
本节对于生成高质量、以用户为中心的文档（如发行说明或开发路线图）至关重要。

一个好的摘要可能至少有一个段落的长度。
-->

服务网格的可观测性的重要性作为可管理、可靠和可持续网格系统的基础不容忽视。在 istio 中，在 l4 和 l7 层提供了 accesslog、指标和追踪，以满足用户对可观测性的需求。

在本提案中，我将分析 istio 的可观测性指标。并建议 Kmesh 实现可观测性功能以支持这些指标。以便用户可以无缝使用 Kmesh。

### 动机

<!--
本节用于明确列出此 KEP 的动机、目标和非目标。描述为什么此更改很重要以及对用户的好处。
-->

#### Accesslog

在 [istio ztunnel](https://github.com/istio/ztunnel?tab=readme-ov-file#logging) 中，第 4 层访问日志包含以下指标：

source.addr
source.workload
source.namespace
source.identity

destination.addr
destination.hbone_addr
destination.service
destination.workload
destination.namespace
destination.identity

direction

bytes_sent
bytes_recv
duration

下面显示了获得的 accesslog 的示例：

```console
2024-05-30T12:18:10.172761Z	info access	connection complete
    src.addr=10.244.0.10:47667 src.workload=sleep-7656cf8794-9v2gv src.namespace=ambient-demo src.identity="spiffe://cluster.local/ns/ambient-demo/sa/sleep" 
    dst.addr=10.244.0.7:8080 dst.hbone_addr=10.244.0.7:8080 dst.service=httpbin.ambient-demo.svc.cluster.local dst.workload=httpbin-86b8ffc5ff-bhvxx dst.namespace=ambient-demo 
    dst.identity="spiffe://cluster.local/ns/ambient-demo/sa/httpbin" 
    direction="inbound" bytes_sent=239 bytes_recv=76 duration="2ms"
```

accesslog 需要包含目标和源的身份（地址/工作负载/命名空间/身份）。此外，所需的指标是发送的消息大小 (bytes_sent)、接收的消息大小 (bytes_recv) 和链接的持续时间。

为了让用户能够顺利使用 Kmesh，Kmesh 需要支持这些 accesslog。

#### 指标

为了监控服务行为，Istio 会为进出 Istio 服务网格以及在 Istio 服务网格内的所有服务流量生成指标。这些指标提供有关行为的信息。

参考 [istio ztunnel metric](https://github.com/istio/ztunnel/blob/6532c553946856b4acc326f3b9ca6cc6abc718d0/src/proxy/metrics.rs#L369) ，在第 L4 层，所需的指标是：

```console
connection_opens: 打开的 TCP 连接总数
connection_close: 关闭的 TCP 连接总数
received_bytes: TCP 连接情况下请求期间接收的总字节数大小
sent_bytes: TCP 连接情况下响应期间发送的总字节数大小
on_demand_dns: 使用按需 DNS 的请求总数（不稳定）
on_demand_dns_cache_misses: 按需 DNS 请求的缓存未命中总数（不稳定）
```

上述指标中与 DNS 相关的指标，由于 Kmesh 尚未支持 DNS，我们将在 Kmesh DNS 功能实现后考虑支持它。

因此，Kmesh 首先需要支持 `connection_opens`、`connection_close`、`received_bytes`、`sent_bytes`。

上述指标还包括以下显示的标签：

```console
reporter

source_workload
source_canonical_service
source_canonical_revision
source_workload_namespace
source_principal
source_app
source_version
source_cluster

destination_service
destination_service_namespace
destination_service_name

destination_workload
destination_canonical_service
destination_canonical_revision
destination_workload_namespace
destination_principal
destination_app
destination_version
destination_cluster

request_protocol
response_flag
connection_security_policy

istio_tcp_sent_bytes_total{
    reporter="destination",

    source_workload="sleep",source_canonical_service="sleep",source_canonical_revision="latest",source_workload_namespace="ambient-demo",
    source_principal="spiffe://cluster.local/ns/ambient-demo/sa/sleep",source_app="sleep",source_version="latest",source_cluster="Kubernetes",
    
    destination_service="tcp-echo.ambient-demo.svc.cluster.local",destination_service_namespace="ambient-demo",destination_service_name="tcp-echo",destination_workload="tcp-echo",destination_canonical_service="tcp-echo",destination_canonical_revision="v1",destination_workload_namespace="ambient-demo",
    destination_principal="spiffe://cluster.local/ns/ambient-demo/sa/default",destination_app="tcp-echo",destination_version="v1",destination_cluster="Kubernetes",
    
    request_protocol="tcp",response_flags="-",connection_security_policy="mutual_tls"} 16
```

`Report` 显示指标是在发送方还是接收方。然后是关于源和目标的一些身份信息。这些类似于 accesslog 中的标签。

然后是 `request_protocol`、`response_flag` 和 `connection_security_policy`。`connection_security_policy` 的值是 mutual_tls 和 unknown。

除了 istio 已经可用的指标之外，由于 Kmesh 能够从内核获得[更丰富的指标](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#tcp%E6%8C%87%E6%A0%87)。这将是 Kmesh 的优势。

#### 目标

<!--
列出 KEP 的具体目标。它试图实现什么？我们如何知道这已经成功？
-->

现在很清楚，为了增强 Kmesh 的可观测性，我们需要：

- 从 ebpf 获取所需的指标。
- 从获取的数据生成 accesslog
- 支持通过 Prometheus 查询指标

#### 非目标

<!--
此 KEP 的范围之外是什么？列出非目标有助于集中讨论并取得进展。
-->

- 与 Dns 相关的指标。
- L7 层的指标。

### 提案

<!--
在这里，我们将深入了解提案的具体内容。这应该有足够的细节，以便审阅者可以准确地理解您提出的内容，但不应包括 API 设计或实现之类的内容。什么是期望的结果，我们如何衡量成功？下面的“设计细节”部分用于真正的细节。
-->

Kmesh 需要通过内核收集指标并将它们传递到用户模式。在用户模式下，accesslog 从指标生成。并支持通过 kemsh localhost:15020 查询指标。

### 设计细节

<!--
本节应包含足够的信息，以便可以理解您的更改的具体细节。这可能包括 API 规范（尽管并非总是必需的）甚至代码片段。如果对您的提案将如何实施有任何歧义，则可以在此处进行讨论。
-->

这是因为 Kmesh 需要从内核获取指标并将它们发送到用户模式。我们需要一个 bpf map 来记录指标，作为传输的媒介。

因此，我们需要定义一个包含所有必需指标的 bpf map：

```console
struct conn_value {
  u64 connection_opens;
  u64 connection_closes;
  u64 received_bytes;
  u64 sent_bytes;
  u64 duration;

  __u32 destination; 
  __u32 source;
};
```

上面的目标和源是包含工作负载身份信息的 bpf map。

#### 访问日志

在 TCP 链接终止时，ebpf 通过 bpf map 将此链接中的数据发送到 kmesh-daemon。

依靠此数据生成 accesslog，然后由 kmesh log 打印。

#### 指标

指标的获取方式与 accesslog 相同。

通过 bpf map 获取指标后，我们还必须支持 Prometheus 查询。

1. 将指标公开给 Prometheus Registry 启用 HTTP 监听接口。
2. 启用 HTTP 监听接口。
3. 定期更新指标。每次链接断开时更新指标。

<div align="center">
<img src="pics/observability.svg" width="800" />
</div>

可观测性应在 ads 模式和工作负载模式下实现。

我们现在只考虑实现 l4 层的可观测性。

对于指标功能，提供 15020 端口用于 Prometheus 查询。

#### 测试计划

<!--
**注意：** *在针对发布版本之前不需要。*

在为此增强功能制定测试计划时，请考虑以下事项：
- 除了单元测试之外，是否会有 e2e 和集成测试？
- 如何在隔离状态下以及与其他组件一起进行测试？

无需概述所有测试用例，只需概述总体策略即可。任何在实现中算作棘手的事情，以及任何特别具有挑战性的测试，都应予以说明。

-->

### 替代方案

<!--
您还考虑了哪些其他方法，以及为什么您排除了它们？这些不需要像提案那样详细，但应包括足够的信息来表达该想法以及为什么它不可接受。
-->

<!--
注意：这是 kubernetes 增强提案模板的简化版本。
https://github.com/kubernetes/enhancements/tree/3317d4cb548c396a430d1c1ac6625226018adf6a/keps/NNNN-kep-template
-->
