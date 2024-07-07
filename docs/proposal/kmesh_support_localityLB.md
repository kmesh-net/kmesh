---
title: Locality Load Balancing for Kmesh
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

## Locality Load Balancing for Kmesh

### Summary

Add Locality Load Balancing to Kmesh workload mode.

### Motivation

Currently, Kmesh does not support locality topology-aware load balancing. Locality Load Balancing optimizes performance and reliability in distributed systems by directing traffic to the nearest service instances. This approach reduces latency, enhances availability, and lowers costs associated with cross-region data transfers. It also ensures compliance with data sovereignty regulations and improves the overall user experience by providing faster and more reliable service responses.

### Goals

The purpose of this proposal is to add locality-based topology-aware load balancing capabilities to kmesh workload mode, corresponding to locality load balancing in Ztunnel.

### Proposal

1. prioritize add locality load balancing capabilities in the workload mode.

2. locality load balancing mode: locality failover.

#### locality failover

1. configure

Configure the load balance type (failover or strict) and scope (REGION, ZONE, etc.) in the service. This corresponds to the message LoadBalancing in workload.proto.
```
message LoadBalancing {
  enum Scope {
    UNSPECIFIED_SCOPE = 0;
    REGION = 1;
    ZONE = 2;
    SUBZONE = 3;
    NODE = 4;
    CLUSTER = 5;
    NETWORK = 6;
  }
  enum Mode {
    UNSPECIFIED_MODE = 0;
    STRICT = 1;
    FAILOVER = 2;
  }
  repeated Scope routing_preference = 1;
  Mode mode = 2;
}
```
https://pkg.go.dev/istio.io/istio/pkg/workloadapi#LoadBalancing_Scope

2. calculate locality match rank

Calculate the rank based on the locality of the src and the locality of all target endpoints in the service according to the configuration in loadbalance. This rank indicates the priority of endpoint selection.
- The target endpoints are all healthy endpoints.

3. choose endpoint

Randomly select one endpoint from the group with the highest rank as the service backend.

4. maybe more？ Panic threshold

When the proportion of healthy endpoints in the high-rank group falls below the panic threshold, select endpoints from the next rank group.
- At this time, the "target" in step 2 should include all endpoints, and then the health ratio of endpoints with the same rank will be calculated.
- The endpoints selected by the load balancer should still be healthy ones within that priority level.
- The health information of the workload is obtained through the workload API (Currently, health checking is not considered, so how the external system maintains and passes the health information to the workload API is not within the scope of discussion).

### Design Details

1. New lb_locality_failover_handle at `bpf/kmesh/workload/include/service.h`
```
static inline int lb_locality_failover_handle(ctx_buff_t *ctx, __u32 service_id, __u32 source_workload_id, service_value *service_v)
{
    // 根据service_id获取所有backends信息，根据workloadapi获取的healthStatus将backends放到一个list中

    // 查询service的locality loadbalance配置，包括scope和mode

    // 根据source_workload_id查源的locality信息

    // 根据以上信息计算rank，按rank分组 类似ztunnel逻辑

    // 【可选】考虑是否根据分组内的健康比例，实行panic failover

    // 从rank最高的一组选择目标endpoint返回
    return 0;
}
```

2. we need source workload locality, so we need parse source workload ip and obtain its locality

`bpf/kmesh/workload/include/workload.h`
```
// add source workload map
typedef struct {
    __u32 src_ipv4; // source ip
} __attribute__((packed)) source_workload_key;

typedef struct {
    __u32 upstream_id; // source workload uid for Pod access // 查询对应的workload携带的locality信息
} __attribute__((packed)) source_workload_value;
```

`bpf/kmesh/workload/cgroup_sock.c`
```
static inline int sock4_traffic_control(struct bpf_sock_addr *ctx)
{
    ...
    // get source ip, then get source workload uid by source ip
    DECLARE_SOURCE_WORKLOAD_KEY(ctx, source_workload_k);
    // bpf_sock_addr中有msg_src_ip4是需要的源ip吗？
    // https://github.com/thustorage/lambda-io/blob/2af493986f360283b9f809077157b42427d40d12/libbpf/src/uapi-bpf.h#L4465
    DECLARE_VAR_IPV4(ctx->msg_src_ip4, ip);
    BPF_LOG(DEBUG, KMESH, "source origin addr=[%pI4h:%u]\n", &ip, bpf_ntohs(ctx->user_port));
    source_workload_v = map_lookup_frontend(&srouce_workload_k); // 用map_lookup_frontend 复用现有的frontend map
    if (!source_workload_v) {
        return -ENOENT;
    }
    ...
}
```

`bpf/kmesh/workload/include/frontend.h`
```
static inline int frontend_manager(ctx_buff_t *ctx, frontend_value *frontend_v, source_workload_value *source_workload_v)
{
    ...
    ret = service_manager(ctx, frontend_v->upstream_id, source_workload_v->upstream_id, service_v); // 增加传入source_workload的id
    ...
}
```

`bpf/kmesh/workload/include/service.h`
```
static inline int service_manager(ctx_buff_t *ctx, __u32 service_id, __u32 source_workload_id, service_value *service_v)
{
    ...
    case LB_POLICY_FAILOVER:
        ret = lb_locality_failover_handle(ctx, service_id, source_workload_id, service_v);
        break;
    ...
}
```

3. Add locality and healthStatus information to the backend map, and include corresponding update logic in the control plane.

`bpf/kmesh/workload/include/workload.h`
```
typedef struct {
    __u32 ipv4; // backend ip
    __u32 service_count;
    __u32 service[MAX_SERVICE_COUNT];
    __u32 waypoint_addr;
    __u32 waypoint_port;
    // 增加健康状态 healthStatus
    // 增加locality信息
} __attribute__((packed)) backend_value;
```

Add corresponding fields to the `pkg/controller/workload/bpfcache/backend.go`, and update logic to `pkg/controller/workload/workload_processor.go`


4. Add scope and mode information to the service map, and incorporate corresponding update logic into the control plane.

`bpf/kmesh/workload/include/workload.h`
```
typedef struct {
    __u32 endpoint_count;               // endpoint count of current service  // 可以依据此值，在service内进行遍历组合endpoint_key，查询backend的信息
    __u32 lb_policy;                    // load balancing algorithm
    __u32 service_port[MAX_PORT_COUNT]; // service_port[i] and target_port[i] are a pair, i starts from 0 and max value
                                        // is MAX_PORT_COUNT-1
    __u32 target_port[MAX_PORT_COUNT];
    __u32 waypoint_addr;
    __u32 waypoint_port;
    // 增加相应的配置 scope，mode
} __attribute__((packed)) service_value;
```

Add corresponding fields to the `pkg/controller/workload/bpfcache/service.go`, and update logic to `pkg/controller/workload/workload_processor.go`


more details: [lark document](https://zrsnlqw1xd.feishu.cn/docx/Qpr6dtfe8olpBcx5HNscLotdn8c)