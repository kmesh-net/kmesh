# 将工作负载添加到 Kmesh

## 如何添加工作负载

Kmesh 根据特定的 Kubernetes 标签管理 Pod 流量。您可以通过为命名空间或单个 Pod 贴标签来注册工作负载。

### 命名空间注册

若要为指定的命名空间启用 Kmesh，请应用 `istio.io/dataplane-mode` 标签并将其值设置为 `kmesh`：

```shell
kubectl label namespace <namespace> istio.io/dataplane-mode=kmesh
```

若要为指定的命名空间禁用 Kmesh，请移除该标签：

```shell
kubectl label namespace <namespace> istio.io/dataplane-mode-
```

### Pod 注册

您还可以直接为 Pod 应用 `istio.io/dataplane-mode=kmesh` 标签来注册工作负载。

```shell
kubectl label pod <pod-name> -n <namespace> istio.io/dataplane-mode=kmesh --overwrite
```

若要显式禁用特定 Pod 的 Kmesh 注册，请将标签值设置为 `none`（`istio.io/dataplane-mode=none`）。这将使该 Pod 排除在 Kmesh 管理之外。

## 排除条件

如果 Pod 满足以下任一条件，Kmesh 将不会对其进行管理：

* Pod 中注入了 Istio sidecar。
* Pod 使用了主机网络（`hostNetwork`）。
* Pod 是由 Istio 管理的 waypoint 代理。

## 验证方法

要验证您的工作负载是否已成功注册到 Kmesh，请使用以下方法：

* **注解：** 成功注册后，Pod 将被添加 `kmesh.net/redirection: enabled` 注解。
* **CNI 插件日志：** 检查记录在 Kubernetes 节点上 `/var/run/kmesh` 目录下的 CNI 插件日志。
* **Kmesh Daemon 日志：** 检查 Kmesh daemon 的日志。首先获取 Pod 名称，然后查看其日志：

```shell
kubectl get po -n kmesh-system
kubectl logs <kmesh-pod-name> -n kmesh-system
```
