# Kmesh性能测试

## 测试组网

![perf_network](../../docs/pics/perf_network.png)

## 测试过程

Kmesh采用fortio、dstat做性能测试工具；fortio是一款功能强大的微服务负载测试库，可以统计tp90/tp99/qps等时延吞吐信息；dstat是一款系统信息统计工具，主要用它收集测试过程中CPU使用情况；

- 测试方法

  以并发链接数为变参测试一组fortio性能数据，并同步收集测试过程中的CPU使用率；`test/performance`目录已归档[测试脚本](./test/performance/fortio_perf.sh)；

## 测试执行

```sh
# 测试环境准备
[root@perf]# ./fortio_perf.sh
# 目录下生成测试结果csv表格
[root@perf]# ll
-rw-r--r--. 1 root root    6.1K Nov  5 17:39 fortio_perf_test.csv
```

