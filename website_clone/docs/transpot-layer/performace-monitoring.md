---
sidebar_position: 4
title: Use Grafana to visualize kmesh performance monitoring
---

**NOTE:** This is an immature feature, so we turn it off by default, you can optionally turn it on.

## Preparation

1. Make default namespace managed by Kmesh
2. Set relevant args:
   - Modify `bpf/kmesh/probes/performance_probe.h` by changing `#define PERF_MONITOR 0` to `#define PERF_MONITOR 1`.
   - Change `--profiling=false` to `--profiling=true` in `deploy/yaml/kmesh.yaml`. (The default value of `--profiling` is false.)
3. Deploy bookinfo as sample application and sleep as curl client
4. Install namespace granularity waypoint for default namespace

   *The above steps could refer to [Install Waypoint | Kmesh](https://kmesh.net/docs/setup/quick-start)

5. Refer to [quick start](https://kmesh.net/docs/setup/quick-start) to include test pods in kmesh management. Or include default namespace in kmesh management.

6. Use `kmeshctl` to enable all of kmesh's monitoring functions:

```sh
kmeshctl monitoring --all enable
```

1. Deploy prometheus and garafana:

```bash
kubectl apply -f https://raw.githubusercontent.com/kmesh-net/kmesh/main/samples/addons/prometheus.yaml
kubectl apply -f https://raw.githubusercontent.com/kmesh-net/kmesh/main/samples/addons/grafana.yaml
```

## Generate some continuous traffic between applications in the mesh

```bash
kubectl exec deploy/sleep -- sh -c "while true; do curl -s http://productpage:9080/productpage | grep reviews-v.-; sleep 1; done"
```

## Use grafana to visualize kmesh performance monitoring

1. Use the port-forward command to forward traffic to grafana:

```bash
kubectl port-forward --address 0.0.0.0 svc/grafana 3000:3000 -n kmesh-system
# Forwarding from 0.0.0.0:3000 -> 3000
```

2. View the dashboard from browser

   Visit `Dashboards > Kmesh > Kmesh performance monitoring`:

    ![image](images/kmesh_deamon_monitoring.jpg)
    ![image](images/kmesh_map_and_operation_monitoring.jpg)

## Cleanup

1. Remove prometheus and grafana:

```bash
kubectl delete -f https://raw.githubusercontent.com/kmesh-net/kmesh/main/samples/addons/prometheus.yaml
kubectl delete -f https://raw.githubusercontent.com/kmesh-net/kmesh/main/samples/addons/grafana.yaml
```
