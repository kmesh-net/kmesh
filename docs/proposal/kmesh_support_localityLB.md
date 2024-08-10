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

Locality load balancing mode: locality failover, locality strict.

What is locality failover: When a flow accesses the service, the control plane will perform a tiered match between the locality information of the originating pod of the flow and the localities of all healthy backends behind the service. Pods with a higher degree of match indicate that they are geographically closer, and traffic will be preferentially routed to pods with a higher matching pair.

What is locality strict: It is a mode within the locality failover mechanism. In locality failover, backends with no match at all are considered the lowest priority; in strict mode, backends that have absolutely no match are eliminated and traffic is not routed to these unmatched backends at all.

### Design Details

#### configure
ref: https://pkg.go.dev/istio.io/istio/pkg/workloadapi#LoadBalancing_Scope
1. Configure the load balance mode (failover or strict) and scope (REGION, ZONE, etc.) of the service. This corresponds to the message LoadBalancing in workload.proto.
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

Add scope and mode information to the service map, and incorporate corresponding update logic into the control plane.

`bpf/kmesh/workload/include/workload.h`
```
typedef struct {
    __u32 endpoint_count;               // endpoint count of current service
    __u32 lb_policy;                    // load balancing algorithm
    __u32 service_port[MAX_PORT_COUNT]; // service_port[i] and target_port[i] are a pair, i starts from 0 and max value
                                        // is MAX_PORT_COUNT-1
    __u32 target_port[MAX_PORT_COUNT];
    struct ip_addr wp_addr;
    __u32 waypoint_port;
    __u8 balance_scope[MAX_SCOPE_COUNT]; // balance scope 
    __u8 balance_mode;                   // balance mode: Unspecified_mode 0; strict 1; failover 2
} service_value;
```

Add corresponding fields to the `pkg/controller/workload/bpfcache/service.go`, and update logic to `pkg/controller/workload/workload_processor.go`

2. Configure the locality (region, zone, subzone) and health status （HEALTHY, UNHEALTHY）of the backend. This corresponds to the message in workload.proto.
```
message Locality {
  string region = 1;
  string zone = 2;
  string subzone = 3;
}

message Workload {
    ...
    WorkloadStatus status = 17;
    Locality locality = 24;
    ...
}
enum WorkloadStatus {
  // Workload is healthy and ready to serve traffic.
  HEALTHY = 0;
  // Workload is unhealthy and NOT ready to serve traffic.
  UNHEALTHY = 1;
}
```

Add locality and healthStatus information to the backend map, and include corresponding update logic in the control plane.

`bpf/kmesh/workload/include/workload.h`
```
typedef struct {
    __u32 region;
    __u32 zone;
    __u32 subzone;
} locality_t;

typedef struct {
    struct ip_addr addr;
    __u32 service_count;
    __u32 service[MAX_SERVICE_COUNT];
    struct ip_addr wp_addr;
    __u32 waypoint_port;
    __u8 health_status; // workload_health_status_t: HEALTHY, UNHEALTHY
    locality_t locality;
} backend_value;
```

Add corresponding fields to the `pkg/controller/workload/bpfcache/backend.go`, and update logic to `pkg/controller/workload/workload_processor.go`


#### New lb_locality_failover_handle 
at `bpf/kmesh/workload/include/service.h` to calculate locality match rank

```
static inline int lb_locality_failover_handle(ctx_buff_t *ctx, __u32 service_id, __u32 source_workload_id, service_value *service_v)
```

Calculate the rank based on the locality of the src and the locality of all target backends in the service according to the configuration in loadbalance. This rank indicates the priority of backends selection. During the computation, backends with a status of unhealthy will be skipped.

![locality_lb_pic](pics/locality_lb.svg)

- A new prio map has been introduced to temporarily store the computed ranks along with their corresponding backends.
    ```
    // prio map
    typedef struct {
        __u32 rank;
    } prio_key;
    typedef struct {
        __u32 count; // count of current prio
        __u32 backend_uid_list[MAP_SIZE_OF_BACKEND]; // workload_uid to uint32
    } prio_value;
    struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, sizeof(prio_key));  // prio
        __type(value, sizeof(prio_value));  // backend id list
        __uint(max_entries, MAX_SCOPE_COUNT);
        __uint(map_flags, BPF_F_NO_PREALLOC);
    } map_of_lb_prio SEC(".maps");
    ```
- Query the locality of the origin workload.

    Add src ip field to `kmesh_context` and parse source ip in `cgroup_sock.c`
    ```
    struct kmesh_context {
        // input
        struct bpf_sock_addr *ctx;
        struct ip_addr orig_dst_addr;
        struct ip_addr orig_src_addr; // src addr

        // output
        struct ip_addr dnat_ip;
        __u32 dnat_port;
        bool via_waypoint;
    };
    ```
    Reusing the backend workload information stored in the frontend, search source workload with source ip. If the information cannot be retrieved, it is assumed that the traffic originates from outside the cluster, and the system falls back to random load balancing.

- Calculate rank as priolity

    Iterate through and compare the locality information of the source workload with every backend associated with the service. If the health status of a backend is unhealthy, skip it; otherwise, match according to the routing rules defined in the service's load balance scope. 
    
    For example, if the service is configured with a region scope, then the region of the source workload is compared with the region of the target backend, adding one to the rank value (rank value) if they are the same. 
    
    After comparing each backend, store the uid of that backend into the prio_value.backend_uid_list corresponding to its rank value as key. Each rank corresponds to a set of backends for that priority level.
    
    If there is no match for all scopes and the mode is set to strict, then the backend will be skipped.

- Choose backend

    Randomly select one backend from the group with the highest rank as the service backend. If there are no workloads at the highest priority level (in the current Locality configuration, a rank of 3 indicates the highest priority), then looks into the next lower priority level (eg. rank 2), and so on, proceeding in a stepwise manner.
