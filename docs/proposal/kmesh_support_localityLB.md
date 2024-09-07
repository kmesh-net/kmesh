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

Currently, Kmesh does not support locality aware load balancing. Locality Load Balancing optimizes performance and reliability in distributed systems by directing traffic to the nearest service instances. This approach reduces latency, enhances availability, and lowers costs associated with cross-region data transfers. It also ensures compliance with data sovereignty regulations and improves the overall user experience by providing faster and more reliable service responses.

### Goals

The purpose of this proposal is to add locality aware load balancing capabilities to kmesh workload mode, corresponding to locality load balancing in Ztunnel.

### Proposal

Locality load balancing mode: locality failover, locality strict.

What is locality failover mode? When a request accesses the service, the control plane will perform a tiered match between the locality information of the originating pod of the flow and the localities of all healthy backends behind the service. Pods with a higher degree of match indicate that they are geographically closer, and traffic will be preferentially routed to pods with a higher matching pair.

What is locality strict mode? In locality strict mode, the LB (load balancing) algorithm will only select backends that exactly match the routingPreference. This means that in such a mode, the load balancer enforces a strict policy where it only routes traffic to backends based on a perfect match with the specified locality preferences, ensuring that requests are handled by servers that meet specific criteria related to their location or other attributes.

### Design Details

Maintain a prio map in both user space and kernel space, where the key is a combination of service ID and rank, and the value consists of a count and a UID list. In user space, compute the rank for each backend corresponding to a service and store it in a BPF map named KmeshPrio. In kernel space, iterate through the ranks using the service ID to query KmeshPrio and perform locality load balancing on the UID list.

![locality_lb_pic](pics/locality_lb.svg)

#### Control plane（user-space）
1. The user-space kmesh process maintains locality, clusterId, and network information, which is updated when xDS receives information about the workload currently on this node. [handleWorkload]
2. The user-space kmesh also maintains routingPreference, which is updated when xDS receives information about the service currently on this node. [storeServiceData]
3. The user-space kmesh maintains a map, `backendsByService`, storing all services present within the current kmesh process along with their respective backends, which will participate in the locality rank calculation.
4. Once both sets of information are maintained, the locality rank is calculated and the locality load balancing policy is updated in the BPF map `KmeshPrio` via the method `[updateLocalityLBPrio]`:
  - `updateLocalityLBPrio`: Iterates through and compares the locality information of the kmesh process with every backend associated with the service, matching according to the routing rules defined in the service's load balance scope. For example, if the service is configured with a region scope, the region of the kmesh process is compared with the region of the target backend, incrementing the rank value if they match. After comparing each backend, store the UID of that backend in the `UidList` of `PrioValue` corresponding to its rank value and service ID as the key. Each rank corresponds to a set of backends for that priority level.
  - In `handleWorkload`, when handling workloads with service information, first execute the existing logic `handleDataWithService` to handle the service, then use `storeServiceBackend` to store the backend in `backendsByService`, and finally call `updateLocalityLBPrio`.
  - In `handleService`, call `updateLocalityLBPrio`.
  - In `removeWorkloadFromLocalityLBPrio`, perform a full update (since removing a workload requires updating the entire map, as the current `prio map` stores the backend UID list in an array form, making selective deletion of map elements impractical).

#### Data plane（kernel-space）
When a request is made for a service, the BPF program queries the backend UID list from the prio map using the request's service ID and iterates through the ranks. 
- In strict mode, it selects backends that match all scopes.
- In failover mode, it traverses the backend UID array starting from the highest rank and decrementing step by step. 
- From the queried backend UIDs, a backend is randomly selected to serve the request.


#### data struct
1. prio map

workload.h
```
typedef struct {
    __u32 service_id; // service id
    __u32 rank; // rank
} prio_key;
typedef struct {
    __u32 count; // count of current prio
    __u32 uid_list[MAP_SIZE_OF_PRIO]; // workload_uid to backend
} prio_value;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(prio_key));
    __uint(value_size, sizeof(prio_value));
    __uint(max_entries, MAP_SIZE_OF_SERVICE*MAX_PRIO);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_of_prio SEC(".maps");

```

2. service

workload.h
```
typedef struct {
    __u32 endpoint_count;               // endpoint count of current service
    __u32 lb_policy;                    // load balancing algorithm, currently supports random algorithm, locality loadbalance Failover/strict mode
    __u32 lb_strict_index;
    __u32 service_port[MAX_PORT_COUNT]; // service_port[i] and target_port[i] are a pair, i starts from 0 and max value
                                        // is MAX_PORT_COUNT-1
    __u32 target_port[MAX_PORT_COUNT];
    struct ip_addr wp_addr;
    __u32 waypoint_port;
} service_value;
```

3. locality LB mode

workload_common.h
```
// loadbalance type
typedef enum {
    LB_POLICY_RANDOM = 0,
    LB_POLICY_STRICT = 1,
    LB_POLICY_FAILOVER = 2,
} lb_policy_t;
```

4. prio

priority.go
```
const (
	MaxPrio       = 7
	MaxSizeOfPrio = 1000
)

type PrioKey struct {
	ServiceId uint32
	Rank      uint32
}
type PrioValue struct {
	Count   uint32                // count of current prio
	UidList [MaxSizeOfPrio]uint32 // workload_uid to backend
}
...
```

5. add new locality info to kmesh process
```
type Processor struct {
	ack *service_discovery_v3.DeltaDiscoveryRequest
	req *service_discovery_v3.DeltaDiscoveryRequest

	hashName *HashName
	// workloads indexer, svc key -> workload id
	endpointsByService      map[string]map[string]struct{}
	backendsByService       map[string]map[string]*workloadapi.Workload
	bpf                     *bpf.Cache
	nodeName                string                            // init from env("NODE_NAME")
	clusterId               string                            // init from workload
	network                 string                            // init from workload
	routingPreference       []workloadapi.LoadBalancing_Scope // init from service
	locality                workloadapi.Locality              // the locality of node, init from workload
	WorkloadCache           cache.WorkloadCache
	ServiceCache            cache.ServiceCache
	is_locality_ok          bool
	is_routingPreference_ok bool
}
```