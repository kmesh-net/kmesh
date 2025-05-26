---
title: 简短、描述性的标题
authors:
- "@zhxuzhonghu"
reviewers:
- 
approvers:
- 


creation-date: 2024-05-08

---

## 在集群管理器中支持 DNS 解析

<!--
这是您的 KEP 的标题。保持简短、简单和描述性。一个好的标题可以帮助传达 KEP 的内容，并且应该被视为任何审查的一部分。
-->

### 摘要

<!--
本节对于生成高质量、以用户为中心的文档（如发行说明或开发路线图）非常重要。
一个好的摘要可能至少有一个段落的长度。
-->

Envoy 支持许多不同的集群类型，包括 `Strict DNS`、`Logical DNS`。但是，鉴于 Kmesh 在内核中使用 ebpf 工作。以前 Kmesh 不支持任何 DNS 类型的集群。对于匹配这些集群的流量，将被丢弃。

在这个提案中，我建议改进 Kmesh 以支持 DNS 类型的集群，这样我们就可以支持所有类型的集群。

### 动机

<!--
本节用于明确列出 KEP 的动机、目标和非目标。描述为什么更改很重要以及对用户的好处。
-->

在 istio 中，[外部名称服务](https://kubernetes.io/docs/concepts/services-networking/service/#externalname) 和 DNS 解析类型的 [ServiceEntry](https://istio.io/latest/docs/reference/config/networking/service-entry/#ServiceEntry-Resolution) 被广泛使用。对于这两种配置，istiod 将生成关联的 DNS 类型集群。

很多人都依赖这种服务，Kmesh 必须支持它，才能让人们无缝迁移到它。

假设我们创建一个如下所示的 ServiceEntry：

```yaml
apiVersion: networking.istio.io/v1
kind: ServiceEntry
metadata:
  name: se
  namespace: default
spec:
  hosts:
  - news.google.com
  ports:
  - name: port1
    number: 80
    protocol: HTTP
  resolution: DNS
```

它将导致如下所示的集群：

```json
{
    "name": "outbound|80||news.google.com",
    "type": "STRICT_DNS",
    "connectTimeout": "10s",
    "lbPolicy": "LEAST_REQUEST",
    "loadAssignment": {
        "clusterName": "outbound|80||news.google.com",
        "endpoints": [
            {
                "locality": {},
                "lbEndpoints": [
                    {
                        "endpoint": {
                            "address": {
                                "socketAddress": {
                                    "address": "news.google.com",
                                    "portValue": 80
                                }
                            }
                        },
                        "metadata": {
                            "filterMetadata": {
                                "istio": {
                                    "workload": ";;;;"
                                }
                            }
                        },
                        "loadBalancingWeight": 1
                    }
                ],
                "loadBalancingWeight": 1
            }
        ]
    },
    "dnsRefreshRate": "60s",
    "respectDnsTtl": true,
    "dnsLookupFamily": "V4_ONLY",
    "commonLbConfig": {
        "localityWeightedLbConfig": {}
    },
    ...
}
```

#### 目标

<!--
列出 KEP 的具体目标。它试图实现什么？我们如何知道它已经成功？
-->

现在很清楚，我们想要：

- 支持 DNS 解析类型的服务管理，工作负载可以访问 DNS 服务。

#### 非目标

<!--
此 KEP 的范围之外是什么？列出非目标有助于集中讨论并取得进展。
-->

- 不要捕获应用程序 DNS 解析请求。

- 不要为应用程序提供节点本地 DNS 服务，至少这不是本提案的目标。

- 由于 istiod 不支持工作负载 DNS 解析，Kmesh 在工作负载模式下也不支持它。

### 提案

<!--
在这里，我们将详细介绍提案的实际内容。这应该有足够的细节，以便审阅者可以准确地理解您提出的内容，但不应包括 API 设计或实现之类的内容。什么是期望的结果，我们如何衡量成功？下面的“设计细节”部分用于真正的细节。
-->

我们应该实现一个新的组件来执行 DNS 解析，称为 `dns resolver`（DNS 解析器）。它应该主要做：

- DNS 解析 DNS 类型集群中的端点

- 将结果记录在 DNS 名称表中

- 定期刷新 DNS 名称表，遵循 `dnsRefreshRate` 或 DNS ttl。

我们还应该提供一种方法，让 ebpf 集群管理器程序访问 DNS 名称表。

### 设计细节

<!--
本节应包含足够的信息，以便可以理解您的更改的具体细节。这可能包括 API 规范（尽管并非总是必需的）甚至代码片段。如果对如何实施您的提案有任何歧义，请在此处进行讨论。
-->

理论上，我们可以考虑在内核或用户空间中实现 DNS 解析器。考虑到复杂性，我建议我们在 Kmesh 守护程序中执行此操作。

![DNS Resolver Arch](./pics/dns-resolver.svg)

`DNS Resolver` 以 ads 模式工作，因此仅在启用 ads 时运行。它与 ads 控制器协作，整个工作流程是：

- ads 控制器负责从 istiod 订阅 xDS，当它收到具有 DNS 类型的集群时，它会通过通道通知 `DNS Resolver`。

- `DNS Resolver` 负责使用 Kmesh 守护程序中的 DNS 配置解析 DNS 域名。

- 解析后，`DNS Resolver` 将通过更新 bpf 哈希映射来设置名称表。

- 重要的是但未在图中描述，`DNS Resolver` 应通过遵循 `dnsRefreshRate` 和 ttl（以较短者为准）定期刷新 DNS 地址。

至于 DNS 解析，package `github.com/miekg/dns` 提供了很好的库，可用于执行 DNS 解析或 DNS 服务。虽然这里不支持 DNS 服务，但我们应该选择一个确实具有这种功能的包，以便将来可以扩展它。建议使用此包的另一个原因是，coredns 也使用了它，因此它在生产中被广泛使用。

我们应该确保没有 DNS 名称可以泄漏。集群在服务删除后被删除是很常见的。现在在 Kmesh 中，我们使用 Stow xDS，每次收到 CDS 响应时，它都会包含网格中的所有集群。ads 控制器解析它们，响应，然后将它们存储在用户空间缓存和 bpf 映射中。我们可以让 ads 控制器也执行 `Stow` 通知。更清楚地说，当 ads 控制器解析所有集群时，它应该将所有需要解析的 DNS 域名发送到 `DNS Resolver`。

由于通知是通过 golang 通道进行的，因此效率很高，`Stow` 应该可以正常工作。在 `DNS Resolver` 中，它应该创建一个 map 来记录它需要解析的所有 DNS 域名。因此，每次通知它都应该能够区分新添加、已删除和未更改的 DNS 域名。

对于新添加的域名，它应该立即解析它们并将结果写入 DNS 名称表，最后将它们推送到刷新队列中。对于已删除的域名，它应该从本地缓存和定期刷新队列中删除它们。对于未更改的域名，它可以什么都不做。

#### 测试计划

<!--
**注意：** *在针对发布版本之前不需要。*
在为此增强功能制定测试计划时，请考虑以下事项：
- 除了单元测试之外，是否会有 e2e 和集成测试？
- 如何在隔离状态下与其他组件一起进行测试？
无需概述所有测试用例，只需概述总体策略即可。任何在实现中被认为是棘手的事情，以及任何特别难以测试的事情，都应该被提出来。
-->

### 替代方案

<!--
您还考虑了哪些其他方法，以及为什么您排除了它们？这些不需要像提案那样详细，但应该包含足够的信息来表达这个想法以及为什么它是不可接受的。
-->

<!--
注意：这是 kubernetes 增强提案模板的简化版本。
https://github.com/kubernetes/enhancements/tree/3317d4cb548c396a430d1c1ac6625226018adf6a/keps/NNNN-kep-template
-->
