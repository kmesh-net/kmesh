---
title: Kmesh 的本地性负载均衡
authors:
- "@derekwin" # Authors' GitHub accounts here.
reviewers:
- "@kwb0523"
- "@hzxuzhonghu"
approvers:
- "@robot"
- TBD

creation-date: 2024-06-07

---

## Kmesh 的本地性负载均衡

### 摘要

为 Kmesh 工作负载模式添加本地性负载均衡。

### 动机

目前，Kmesh 不支持本地性感知负载均衡。本地性负载均衡通过将流量导向最近的服务实例来优化分布式系统中的性能和可靠性。这种方法减少了延迟，提高了可用性，并降低了与跨区域数据传输相关的成本。它还确保了符合数据主权法规，并通过提供更快、更可靠的服务响应来改善整体用户体验。

### 目标

本提案的目的是为 kmesh 工作负载模式添加本地性感知负载均衡能力，对应于 istio ambient mesh 中的本地性负载均衡。

### 提案

本地性负载均衡模式：本地性故障转移，本地性严格。

什么是本地性故障转移模式？当请求访问服务时，控制平面将对流量的源 pod 的本地性信息与服务背后所有健康后端的本地性进行分层匹配。匹配度更高的 Pod 表示它们在地理位置上更接近，流量将优先路由到匹配度更高的 Pod。

什么是本地性严格模式？在本地性严格模式下，LB（负载均衡）算法将仅选择与 routingPreference 完全匹配的后端。这意味着在这种模式下，负载均衡器会强制执行严格的策略，仅根据与指定本地性偏好的完全匹配将流量路由到后端，从而确保请求由满足与其位置或其他属性相关的特定标准的服务器处理。

### 设计细节

1. 在 BPF 侧的 `service_manager` 中实现新的负载均衡处理逻辑：`lb_locality_failover_handle`。
2. 向 BPF 侧的数据结构添加了更多必要的信息：map `service_value` 存储负载均衡策略 `lb_policy` 和一个数组 `prio_endpoint_count[PRIO_COUNT]`，用于计算不同优先级的端点。map `endpoint_key` 存储当前端点的优先级 `prio`。
3. 在用户侧添加了一个 `locality_cache` 模块，用于存储本地性感知信息和优先级计算逻辑。
4. 更新了用户侧的 `ServiceValue` 和 `EndpointKey` map。
5. 我们通过更新 `EndpointKey` 动态维护与不同优先级对应的端点。为了在更新策略时更新 `EndpointKey`，我们添加了一个 `endpoint_cache` 来存储额外的端点信息。
6. 在 `workload_processor` 中，我们更新了添加和删除端点和服务的逻辑，以及在处理工作负载和服务 xDs 信息时更新相应 map 信息的逻辑。我们在 `handleWorkloadUnboundServices` 中实现了 LB 更新逻辑。为了确保服务的连续性，我们考虑了策略切换期间的场景，并逐一实现了 `endpointKey` 更新。
7. 对于随机策略，所有端点都标记为优先级 0。对于故障转移或严格策略，根据 `routingPreference`，优先级设置为与最高匹配的端点为 0。

#### 控制流
<div style="text-align:center"><img src="pics/locality_lb.svg" /></div>

#### 数据结构
1. workload.h
```
typedef struct {
    __u32 prio_endpoint_count[PRIO_COUNT]; // endpoint count of current service with prio
    __u32 lb_policy; // load balancing algorithm, currently supports random algorithm, locality loadbalance
                     // Failover/strict mode
    __u32 service_port[MAX_PORT_COUNT]; // service_port[i] and target_port[i] are a pair, i starts from 0 and max value
                                        // is MAX_PORT_COUNT-1
    __u32 target_port[MAX_PORT_COUNT];
    struct ip_addr wp_addr;
    __u32 waypoint_port;
} service_value;

// endpoint map
typedef struct {
    __u32 service_id;    // service id
    __u32 prio;          // 0 means heightest prio, match all scope, 6 means lowest prio.
    __u32 backend_index; // if endpoint_count = 3, then backend_index = 0/1/2
} endpoint_key;
```

2. workload_common.h
```
// loadbalance type
typedef enum {
    LB_POLICY_RANDOM = 0,
    LB_POLICY_STRICT = 1,
    LB_POLICY_FAILOVER = 2,
} lb_policy_t;
```

3. endpoint.go
```
const (
	PrioCount = 7
)

type EndpointKey struct {
	ServiceId    uint32 // service id
	Prio         uint32
	BackendIndex uint32 // if endpoint_count = 3, then backend_index = 1/2/3
}
```

4. locality_cache.go
```
// localityInfo records local node workload locality info
type localityInfo struct {
	region    string // init from workload.GetLocality().GetRegion()
	zone      string // init from workload.GetLocality().GetZone()
	subZone   string // init from workload.GetLocality().GetSubZone()
	nodeName  string // init from os.Getenv("NODE_NAME"), workload.GetNode()
	clusterId string // init from workload.GetClusterId()
	network   string // workload.GetNetwork()
}

type LocalityCache struct {
	mutex        sync.RWMutex
	LocalityInfo *localityInfo
}
```

5. service.go
```
type ServiceValue struct {
	EndpointCount [PrioCount]uint32 // endpoint count of current service
	LbPolicy      uint32            // load balancing algorithm, currently only supports random algorithm
	ServicePort   ServicePorts      // ServicePort[i] and TargetPort[i] are a pair, i starts from 0 and max value is MaxPortNum-1
	TargetPort    TargetPorts
	WaypointAddr  [16]byte
	WaypointPort  uint32
}
```

6. endpoint_cache.go
```
type Endpoint struct {
	ServiceId    uint32
	Prio         uint32
	BackendIndex uint32
}

type EndpointCache interface {
	List(uint32) map[uint32]Endpoint // Endpoint slice by ServiceId
	AddEndpointToService(Endpoint, uint32)
	DeleteEndpoint(Endpoint, uint32)
	DeleteEndpointByServiceId(uint32)
}
```

