---
sidebar_position: 2
title: 流量分割
---

### 开始之前

#### 在 Ads-v1 模式下安装 Kmesh

1. 导航至 [快速入门](/i18n/zh/docusaurus-plugin-content-docs/current/setup/quick-start.md) 文档
2. 在标题为 `更改 Kmesh 启动模式` 的部分
3. 打开配置文件：`deploy/charts/kmesh-helm/values.yaml`
4. 将 `--mode=ads-v2` 替换为 `--mode=ads-v1`

此配置更改是流量分割功能正常工作的必要条件。

#### 部署示例应用程序

```shell
[root@master kmesh]# kubectl apply -f samples/sleep/sleep.yaml -n tcp-echo-test
[root@master kmesh]# kubectl apply -f samples/tcp-echo/tcp-echo-services.yaml -n tcp-echo-test
[root@master kmesh]# kubectl apply -f samples/tcp-echo/tcp-echo-virtualservice.yaml -n tcp-echo-test
```

### 应用基于权重的负载均衡

1. 让 Kmesh 管理 Pod 的流量

   ```shell
   [root@master test]# kubectl label ns default istio.io/dataplane-mode=Kmesh
   ```

2. 通过发送一些 TCP 流量来确认 `tcp-echo` 服务正在运行。

   ```shell
   ## 获取 tcp-echo 服务地址
   [root@master test]# kubectl get svc | grep tcp-
   tcp-echo  ClusterIP  10.96.128.249 <none>  9000/TCP,9001/TCP 43h
   [root@master test]# for i in {1..20}; do kubectl exec sleep-78ff5975c6-cm8hd -c sleep -- sh -c "(date; sleep 1) | nc  10.96.128.249:9000;" done
   two Sat Jul  6 08:46:45 UTC 2024
   two Sat Jul  6 08:46:46 UTC 2024
   one Sat Jul  6 08:46:47 UTC 2024
   one Sat Jul  6 08:46:48 UTC 2024
   two Sat Jul  6 08:46:49 UTC 2024
   two Sat Jul  6 08:46:51 UTC 2024
   two Sat Jul  6 08:46:52 UTC 2024
   one Sat Jul  6 08:46:53 UTC 2024
   two Sat Jul  6 08:46:54 UTC 2024
   two Sat Jul  6 08:46:55 UTC 2024
   one Sat Jul  6 08:46:56 UTC 2024
   one Sat Jul  6 08:46:57 UTC 2024
   two Sat Jul  6 08:46:58 UTC 2024
   one Sat Jul  6 08:47:00 UTC 2024
   two Sat Jul  6 08:47:01 UTC 2024
   one Sat Jul  6 08:47:02 UTC 2024
   two Sat Jul  6 08:47:03 UTC 2024
   one Sat Jul  6 08:47:04 UTC 2024
   one Sat Jul  6 08:47:05 UTC 2024
   two Sat Jul  6 08:47:06 UTC 2024
   ```

### 转储配置信息

```shell
[root@master kmesh]# ./kmeshctl dump kmesh-5f4fm ads-v1
```

转储配置后，我们可以看到策略是负载均衡。

```json
{
  "name": "outbound|9001||tcp-echo.default.svc.cluster.local",
  "connectTimeout": 10,
  "lbPolicy": "LEAST_REQUEST",
  "loadAssignment": {
    "clusterName": "outbound|9001||tcp-echo.default.svc.cluster.local",
    "endpoints": [
      {
        "lbEndpoints": [
          {
            "address": {
              "port": 10531,
              "ipv4": 469890058
            }
          },
          {
            "address": {
              "port": 10531,
              "ipv4": 453112842
            }
          }
        ],
        "loadBalancingWeight": 2
      }
    ]
  },
  "circuitBreakers": {
    "maxConnections": 4294967295,
    "maxPendingRequests": 4294967295,
    "maxRequests": 4294967295,
    "maxRetries": 4294967295
  }
}
```
