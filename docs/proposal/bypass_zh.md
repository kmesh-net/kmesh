## 背景

目前，如果服务之间在开启服务网格的情况下通信失败，很难判断问题是因为服务网格接管流量造成的，还是服务本身存在错误。 因此，我们提供了将网格服务从通信流量路径中删除的功能，以查明问题是由服务网格还是应用程序本身的错误引起的。

## 功能设计

bypass是一种通用网格功能，用于从流量路径中删除 sidecar/kmesh 网格服务。 下面两种场景介绍了启用bypass功能后的流量路径。

### 场景一：sidecar

下面两张图中，在集群中启用了sidecar来接管流量。 图一为启用bypass功能前的流量路径。从中我们可以看到，流量路径是服务A->sidecar->sidecar->服务B，当服务A和服务B通信失败时，从黑盒层面，用户无法判断是否是 sidecar 或服务本身存在问题。 图二中，开启了pod1的bypass功能，从而pod1中的sidecar会被从流量路径中移除。 如果此时服务A和服务B能够正常通信，则证明sidecar存在问题。

![alt text](pics/sidecar_pre_bypass.svg)

![alt text](pics/sidecar_bypass.svg)

### 场景二：kmesh

在图一中，流量路径是服务A->kmesh->服务B。在图二中，开启了bypass功能后，会在kmesh的ebpf程序中判断bypass功能已经开启，从而kmesh不会接管服务A发出的数据，流量路径是服务A->服务B。如果此时服务A和服务B能够正常通信，则证明kmesh存在问题。

![alt text](pics/kmesh_pre_bypass.svg)

![alt text](pics/kmesh_bypass.svg)

## Bypass的数据结构

```c
struct bpf_map_def SEC("maps") bypass_fliter_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 256,
};
```

key代表pod的IP地址，value代表当前pod是否开启bypass功能，用0/1表示。 当执行到这个ebpf程序时，它会检查对应的pod是否启用了bypass功能。 如果启用，则所有后续的 iptables 规则都将被短路，且出入方向的流量都将被短接。反之则不会短接后续的iptables规则。

## 如何开启bypass

执行以下命令:

```shell
kubectl label pod <pod_name> kmesh.net/bypass=enabled
```

这将会导致一个pod的出入流量都将被短接

## 如何观测label的变化

Kmesh Daemon 通过与 Kubernetes API Server 通信，使用字段选择器实现了对特定标签的观测。它观察 Kubernetes API Server 的变化，并过滤所需的资源对象，从而只观测特定标签的变化。

```go
informerFactory := informers.NewSharedInformerFactoryWithOptions(client, 0,
    informers.WithTweakListOptions(func(options *metav1.ListOptions) {
        options.FieldSelector = fmt.Sprintf("spec.nodeName=%s", nodeName)
        options.LabelSelector = "kmesh.net/bypass=enabled"
    }))

podInformer := informerFactory.Core().V1().Pods()
```

## 流量治理流程

### 场景一：sidecar

![alt text](pics/sidecar_traffic_path.svg)

上图中黑色箭头表示的路径是bypass功能开启前的流量路径，蓝色箭头是bypass功能开启后的流量路径。 不同的是，启用bypass功能后，kmesh mda会在iptables规则的顶层添加两条。 规则是：

```shell
iptables -t nat -I OUTPUT -m bpf --object-pinned /sys/fs/bpf/bypass -j RETURN
iptables -t nat -I PREROUTING -m bpf --object-pinned /sys/fs/bpf/bypass -j RETURN
```

这两条规则将导致流量路径在ebpf程序中被更新。 ebpf程序会判断当前pod是否开启了bypass功能。 如果启用该功能，数据将直接发送到对端服务，而不是服务网格中。

### 场景二：kmesh

![alt text](pics/kmesh_traffic_path.svg)

该场景下，上图中蓝色箭头所代表的路径即为旁路功能开启前后的流量路径。 不同之处是在kmesh原有的ebpf程序中增加了对bypass功能的判断。 当前kmesh是否接管流量的依据是ebpf程序是否获取到的classid是否与kmesh定义的classid一致。 如果一致，流量就会被接管。开启了bypass功能之后，还会再判断一次bypass功能是否启用。

## 注意

- 当前bypass功能仅短接单个Pod的服务网格流量，而不是整个流量路径上的服务网格。为了解决短接一方的服务网格之后，导致另一方服务网格无法解析收到的加密报文的问题。 在启用bypass功能之前，需要配置服务网格以明文格式发送消息
- 目前bypass会短接单个Pod的出入方向的流量。 后续还将对出入方向的流量进行细分。 例如，只有出方向的流量会被短路。
