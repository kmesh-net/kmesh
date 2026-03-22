---
sidebar_position: 4  
title: 使用 Grafana 可视化 Kmesh 性能监控  
---

## 准备工作

1. 使默认命名空间由 Kmesh 管理  
2. 设置相关参数：  
   - 修改 `bpf/kmesh/probes/performance_probe.h` 文件，将 `#define PERF_MONITOR 0` 更改为 `#define PERF_MONITOR 1`。  
   - 在 `deploy/yaml/kmesh.yaml` 中，将 `--enable-perfmonitor=false` 更改为 `--enable-perfmonitor=true`。  
3. 部署 bookinfo 作为示例应用程序，并部署 sleep 作为 curl 客户端  
4. 为默认命名空间安装命名空间粒度的 waypoint  

   *以上步骤可参考 [安装 Waypoint | Kmesh](/i18n/zh/docusaurus-plugin-content-docs/current/application-layer/install_waypoint.md#准备工作)*  

5. 部署 Prometheus 和 Grafana：  

```bash
kubectl apply -f https://raw.githubusercontent.com/kmesh-net/kmesh/main/samples/addons/prometheus.yaml
kubectl apply -f https://raw.githubusercontent.com/kmesh-net/kmesh/main/samples/addons/grafana.yaml
```

## 在网格中的应用程序之间生成一些持续的流量

```bash
kubectl exec deploy/sleep -- sh -c "while true; do curl -s http://productpage:9080/productpage | grep reviews-v.-; sleep 1; done"
```

## 使用 Grafana 可视化 Kmesh 性能监控

1. 使用 port-forward 命令将流量转发到 Grafana：  

```bash
kubectl port-forward --address 0.0.0.0 svc/grafana 3000:3000 -n kmesh-system
# Forwarding from 0.0.0.0:3000 -> 3000
```

2. 从浏览器查看仪表板  

   访问 `Dashboards > Kmesh > Kmesh performance monitoring`：  

    ![image](images/kmesh_deamon_monitoring.jpg)  
    ![image](images/kmesh_map_and_operation_monitoring.jpg)  

## 清理

1. 移除 Prometheus 和 Grafana：  

```bash
kubectl delete -f https://raw.githubusercontent.com/kmesh-net/kmesh/main/samples/addons/prometheus.yaml
kubectl delete -f https://raw.githubusercontent.com/kmesh-net/kmesh/main/samples/addons/grafana.yaml
```
