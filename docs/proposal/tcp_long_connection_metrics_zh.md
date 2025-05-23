---
title: 用于生成 TCP 长连接指标的提案
authors: 
 - "yp969803"
reviewers:
- "nglwcy"
- "lizhencheng"
approvers:
- "nlgwcy"
- "lizhencheng"

creation-date: 2025-02-06
---

## 用于生成 TCP 长连接指标的提案

<!--
这是您的 KEP 的标题。保持简短、简单和描述性。一个好的标题可以帮助传达 KEP 是什么，并且应该被视为任何审查的一部分。
-->

Upstream issue: https://github.com/kmesh-net/kmesh/issues/1211

### 摘要

<!--
本节对于生成高质量、以用户为中心的文档（如发行说明或开发路线图）至关重要。

一个好的摘要可能至少有一个段落的长度。
-->

目前，kmesh 在 TCP 连接关闭后提供访问日志，其中包含有关连接的更详细信息，例如发送的字节数、接收的字节数、丢包数、rtt 和重传数。

Kmesh 还提供工作负载和服务特定的指标，例如发送和接收的字节数、丢失的数据包、最小 rtt、pod 打开和关闭的总连接数。这些指标仅在连接关闭后更新。在本提案中，我们的目标是定期更新这些指标。

我们还旨在实现 TCP 长连接的访问日志和指标，开发一种连续监控和报告机制，以捕获长寿命 TCP 连接整个生命周期中的详细实时数据。定期报告访问日志，其中包含报告时间、连接建立时间、发送的字节数、接收的字节数、丢包数、rtt、重传数和状态等信息。还会定期报告长连接的指标，例如发送和接收的字节数、丢包数、重传数。

### 动机

<!--
本节用于明确列出此 KEP 的动机、目标和非目标。描述为什么此更改很重要以及对用户的好处。
-->

可以尽早了解长连接的性能和健康状况，目前我们通过连接终止后提供的指标和访问日志获取连接的所有信息。

#### 目标

<!--
列出 KEP 的具体目标。它试图实现什么？我们如何知道这已经成功？
-->
- 定期（5 秒）报告基于工作负载和服务的指标。

- 使用 ebpf 在长 TCP 连接的整个生命周期内持续收集详细的流量指标（例如，发送/接收的字节数、往返时间、数据包丢失、tcp 重传）。

- 以 5 秒的周期性时间报告指标和访问日志。我们选择 5 秒作为阈值时间，因为它允许有足够的时间来累积指标中有意义的更改。如果报告间隔太短，可能会因处理过多的更新而导致过多的开销。

- 从指标数据中生成包含有关连接信息的访问日志，并在长 TCP 连接的整个生命周期内持续生成。

- 指标和日志支持 open-telemetry 格式。

- 通过 kmesh 守护程序公开这些指标，以便 prometheus 可以抓取它。

- 单元测试和 E2E 测试。

#### 非目标

<!--
此 KEP 的范围之外是什么？列出非目标有助于集中讨论并取得进展。
-->

- 收集有关数据包内容的信息。

- 控制或修改 TCP 连接

- 收集 L7 指标

### 提案

<!--
在这里，我们将深入了解提案的实际细节。这应该有足够的细节，以便审阅者可以准确地理解您要提出的内容，但不应包括 API 设计或实现之类的内容。什么是期望的结果，我们如何衡量成功？下面的“设计细节”部分用于真正的细节。
-->

TCP 连接信息将使用 eBPF cgroup_skb 钩子收集。RingBuffer map 用于定期将连接信息发送到用户空间。

### 设计细节

<!--
本节应包含足够的信息，以便可以理解您的更改的具体细节。这可能包括 API 规范（尽管并非总是必需的）甚至代码片段。如果对您的提案将如何实施有任何歧义，则可以在此处进行讨论。
-->

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

<!--
详细说明如果实施此 KEP，人们将能够做的事情。包括尽可能多的细节，以便人们可以理解系统的“方式”。这里的目标是让用户感觉真实，而不会陷入困境。
-->

##### 故事 1
工作负载和服务 prometheus 指标会定期更新，并在连接关闭时更新。

##### 故事 2
一个新的 prometheus 指标用于定期更新的长 tcp 连接。

#### 注意事项/约束/警告（可选）

<!--
该提案有哪些注意事项？
上面没有提到哪些重要的细节？
尽可能详细地介绍。
这可能是讨论核心概念以及它们如何相关的好地方。
-->

#### 风险和缓解措施

<!--
此提案有哪些风险，我们如何缓解？

将由谁以及如何审查安全性？

将由谁以及如何审查 UX？

考虑包括在 SIG 或子项目之外工作的人员。
-->

#### 测试计划

<!--
**注意：** *在针对发布版本之前，不是必需的。*

在制定此增强功能的测试计划时，请考虑以下事项：
- 除了单元测试之外，是否还会有 e2e 和集成测试？
- 将如何在隔离状态下以及与其他组件一起进行测试？

无需概述所有测试用例，只需概述总体策略即可。任何在实现中都算作棘手的事情，以及任何特别难以测试的事情，都应予以说明。

-->

更新 bpf_test.go 以测试编写的 ebpf 代码。
同时更新 metric_test.go 以测试指标
### 备选方案

<!--
您还考虑了哪些其他方法，以及为什么您排除了它们？这些不需要像提案那样详细，但应包括足够的信息来表达该想法以及为什么它不可接受。
-->

<!--
注意：这是 kubernetes 增强提案模板的简化版本。
https://github.com/kubernetes/enhancements/tree/3317d4cb548c396a430d1c1ac6625226018adf6a/keps/NNNN-kep-template
-->

创建一个用户空间代理组件而不是 ebpf 来收集指标。
