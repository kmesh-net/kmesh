---
title: Kmesh 性能
sidebar_position: 1
---


## 可观测性集成

Kmesh 通过与行业标准可观测性平台集成，提供全面的监控能力：

- **Prometheus**：收集并存储 Kmesh 性能和操作的指标
- **Grafana**：通过可定制的仪表板可视化 Kmesh 指标
- **Jaeger**：启用分布式追踪以分析服务网格流量模式

这些集成有助于实时监控 Kmesh 的性能指标、资源消耗和流量模式。

## 测试网络设置

![性能网络图](./images/perf_network.png)

## 测试方法

### 测试工具

Kmesh 使用两个主要测试工具：

- **Fortio**：一个微服务负载测试工具，用于测量：
  - 延迟（TP90，TP99）
  - 吞吐量（QPS）
- **Dstat**：一个系统监控工具，用于在测试期间跟踪 CPU 使用情况

### 测试方法

通过使用并发连接数作为变量参数来测试一组 `fortio` 性能数据，并在测试期间收集 CPU 使用情况。[测试脚本](https://github.com/kmesh-net/kmesh/test/performance/)已被归档。

## 运行测试

```shell
#准备测试环境
[root@perf]# ./fortio_perf.sh
# 在目录中生成测试结果的 CSV 表格。
[root@perf]# ll
-rw-r--r--. 1 root root 6.1K Nov 5 17:39 fortio_perf_test.csv
```

## 性能结果

![性能测试结果](./images/fortio_performance_test.png)
