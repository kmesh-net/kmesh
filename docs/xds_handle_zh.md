# Kmesh 中的 xDS 响应处理

Kmesh 现在利用 StoW(state-of-the-world) ADS 从 xDS 控制平面订阅 xDS 资源。目前，我们订阅了四种类型的 xDS 资源，包括 CDS、EDS、LDS 和 RDS。我们将会利用增量 ADS 来订阅从 Ambient Mesh 引入的 `Address` 资源。

我们的目标是设计一个更好的 xDS 缓存，以适应 StoW 和增量 ADS 模式。

## 我们如何订阅 xDS 资源

Kmesh daemon 初始化一个 ADS client，并自动订阅 xDS 资源。对于每种资源，我们都注册了一个相关的资源处理器。我们严格依赖资源处理器来更新 xDS 缓存、维护 bpf map 并向控制平面发送 ACK。这种行为类似于许多其他 xDS client。

![xDS 处理流程图](./pics/xds.svg)

## 缓存状态维护

请注意，我们维护了两级缓存，一个驻留在用户空间，由 ADS 加载器读取和写入。另一个是 bpf map，由 eBPF 代码读取，并由 ADS 加载器写入。因此，ADS 加载器需要知道哪些资源是新添加的，哪些是未更改的，哪些是删除的。

为了使 Kmesh 缓存适应 StoW 和 Delta xDS 模式，首先我们需要了解各自的需求。

### StoW

StoW ADS 返回所有 xDS 资源，在 xDS 处理器中，我们需要将响应与用户空间的 xDS 缓存进行比较，以了解新添加、删除和未更改的资源集合。

### Delta

Delta xDS 返回更新和删除的资源，与 StoW 的区别在于，删除的资源会明确设置在 [DeltaDiscoveryResponse.RemovedResources](https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/discovery/v3/discovery.proto#envoy-v3-api-msg-service-discovery-v3-deltadiscoveryresponse) 中。

![xDS 缓存流程图](./pics/xds_cache.svg)

详细的工作流程如上图所示：
1. xDS 处理器接收到响应后，ADS 加载器将与 xDS 缓存进行比较，以将资源分类为三类：删除（Removed）/更新（Updated）/未更改（Unchanged）。
2. 将更新的资源存储在 xDS 缓存中，将其 API 状态设置为 `ApiStatus_UPDATE`。
3. 将删除的资源的 API 状态更新为 `ApiStatus_DELETE`。
4. 将资源刷新（flush）到 bpf map 中。如果 API 状态为 `ApiStatus_DELETE`，则删除资源；如果 API 状态为 `ApiStatus_UPDATE`，则更新资源，然后将 API 状态从 `ApiStatus_UPDATE` 重置为 `ApiStatus_NONE`。
5. 从用户空间的 xDS 缓存中删除标记为 `ApiStatus_DELETE` 的资源。
