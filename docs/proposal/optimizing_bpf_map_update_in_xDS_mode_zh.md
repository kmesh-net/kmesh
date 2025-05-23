---
title: 优化 xDS 模式下的 bpf map 更新
authors:
- "@nlgwcy"
reviewers:
- "@robot"
- "@hzxuzhonghu"
- "@supercharge-xsy"
- "@bitcoffeeiux"
approvers:
- "@robot"
- TBD

creation-date: 2024-05-13

---

## 优化 xDS 模式下的 bpf map 更新

### 概要

Kmesh 是一个基于网格的数据平面治理转发系统，使用 eBPF 实现。在 xDS 配置分发到 Kmesh-daemon 后，它们会被使用一个库反序列化，然后作为 eBPF map 在内核中更新。然而，更新性能很差。本提案介绍了解决此问题的优化策略。

### 动机

在 xDS 配置更新期间，eBPF map 刷新性能较差，导致对 Istiod 发出的 xDS 更改通知的响应延迟。例如，单个 routeconfig 更新所需的时间约为几秒。性能分析显示，outter_map 表 (ARRAY_OF_MAPS) 上的添加和删除操作相对较慢，每次添加或删除记录的测量时间成本约为 5 毫秒。造成这种情况的主要原因是此类 map 的添加和删除过程中涉及的[同步操作](https://github.com/torvalds/linux/commit/1ae80cf31938c8f77c37a29bbe29e7f1cd492be8)。

[单元测试](https://github.com/kmesh-net/kmesh/blob/1ae49ce4b623bc888ad2386d9acbc531d6c62d67/pkg/cache/v2/cluster_test.go#L180) eBPF map 刷新延迟：

```sh
[root@localhost v2]# go test -bench=. --benchtime=100x
goos: linux
goarch: amd64
pkg: kmesh.net/kmesh/pkg/cache/v2
cpu: Intel(R) Xeon(R) CPU E5-2690 v3 @ 2.60GHz
BenchmarkClusterFlush-16             100         835615271 ns/op
BenchmarkFlush-16                    100        1595920212 ns/op
PASS
ok      kmesh.net/kmesh/pkg/cache/v2    245.370s
[root@localhost v2]#
```

#### 目标

单个 xDS 配置更新的延迟在毫秒范围内。

### 提案

#### eBPF map 更新机制

在 xDS 模型中，配置是分层组织的。当前的设计通过 eBPF map 的 map-in-map 机制实现 map 层次结构。具体实现如下：

- xDS 模型 -> proto-c 数据结构

  ![](pics/kmesh-proto.svg)

- 通过 map-in-map 组织

  ![](pics/kmesh-map-in-map.svg)

  对于 map 记录的 value 成员，如果它是一个涉及引用其他数据结构的指针变量，则实际数据区域存储在 inner-map 中：

  - 如果 value 成员是原始数据类型（例如 int），则可以直接访问它。
  - 如果 value 成员是指针类型，则存储在指针中的值是 outter_map 表中保存实际数据的 inner-map 的索引（注意：该索引在 kmesh-daemon 的 xds-adapter 模块中写入 bpf map 时更新）。访问时，首先根据索引检索 inner-map 的 map fd，然后从 inner-map 表中获取实际数据。对于多级指针成员，重复此过程，直到所有指针信息都被剥离。

  这种设计的好处是：

  - xDS 模型更改不需要重新定义 eBPF map 数据结构，从而提供高度的灵活性。

#### 优化方案

当前的实现方案如下：

- Bitmap 用于管理哪些 inner_map 记录是空闲的，并且 bitmap 信息存储在 outter_map 的第一个记录中。
- 在 xDS 配置创建期间，在 outter_map 中搜索 `idle` idx，并创建相应的 inner_map。inner_map 信息被添加到 outter_map 表中，并且 bitmap 信息被更新为 `used`（outter_map 表也会被更新）。
- 在 xDS 配置删除期间，搜索 outter_map 中记录的 idx，并删除相应的 inner_map 表。outter_map 中的记录也会被删除，并且 bitmap 信息被更新为 `idle`。

正如我们所看到的，一个 xDS 更改涉及多次 outter_map 刷新。以下是优化方法（时空权衡）：

- 当 kmesh-daemon 启动时，一次性创建所有 outter_map 记录（包括 inner_map），由于 outter_map 表更新缓慢，因此使用多个线程并行化刷新过程。
- 在内存中维护一个 `inner_map_mng` 表，该表跟踪每个 idx 的空闲状态及其对应的 inner_map。
- 在 xDS 配置创建期间，对于指针/字符串成员，从 inner_map_mng 中检索一个 `idle` idx 记录，并将实际内容更新到与该 idx 关联的 inner_map 表中。此外，将该记录的状态更新为 `used`。
- 在 xDS 配置删除期间，找到 `inner_map_mng` 中与 idx 对应的记录，并将其状态更新为 `idle`。

![](pics/kmesh-map-in-map-optimization.svg)

#### 风险和缓解措施

这种方法利用了时空权衡。当 outter_map 表的大小设置为相对较大时，不适合一次性创建所有 inner_map 记录，因为它可能导致 kmesh-daemon 的启动时间更长和过多的内存消耗。以下是一些潜在的优化策略：

- 在 kmesh-daemon 初始化期间，仅创建特定大小的 outter_map 记录，然后启动一个后台线程以逐步创建剩余的记录。
- 根据实际使用场景按需创建 outter_map 记录。

#### 测试

优化策略的性能测试结果：

```sh
[root@localhost v2]# go test -bench=. --benchtime=100x
goos: linux
goarch: amd64
pkg: kmesh.net/kmesh/pkg/cache/v2
cpu: Intel(R) Xeon(R) CPU E5-2690 v3 @ 2.60GHz
BenchmarkClusterFlush-16             100            600145 ns/op
BenchmarkFlush-16                    100            283194 ns/op
PASS
ok      kmesh.net/kmesh/pkg/cache/v2    4.047s
```
