---
title: Circuit Breaker
authors:
- "@Okabe-Rintarou-0" # Authors' GitHub accounts here.
reviewers:
- "@supercharge-xsy"
- "@hzxuzhonghu"
- "@nlwcy"
- TBD
approvers:
- "@robot"
- TBD

creation-date: 2024-05-29

---

## Add circuit breaker function in Kmesh

### Summary

Main target:

+ Support circuit breaker.
+ Support outlier detection.
+ Add sufficient unit tests.

### Motivation

The circuit breaker mechanism is typically used to prevent the spread of failures between services, safeguarding system stability and avoiding system crashes or cascading failures caused by a large number of requests. Kmesh currently does not implement the circuit breaker mechanism.

Common scenarios that trigger circuit breakers include:
+ High error rate in the service
+ High latency in the service
+ Exhaustion of service resources
+ Service unavailability
+ Service requests hit the maximum limit
+ Service connections hit the maximum limit

#### Goals

+ Support circuit breaker. Kmesh should be able to parse the circuit breaker config from xds stream and enable corresponding circuit breakers.
+ Support circuit breaker. Kmesh should be able to parse the outlier detection config from xds stream and support outlier detection.
+ Add sufficient unit tests to test the correctness of the functions.

### Design Details

#### Circuit Breaker in Istio

Envoy supports cluster and per-host thresholds(but only the `max_connections` field is now available in per-host thresholds). For more details, please check the [official document](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/circuit_breaker.proto).

> per_host_thresholds
> (repeated config.cluster.v3.CircuitBreakers.Thresholds) Optional per-host limits that apply to each host in a cluster.

Here is the comparison table for settings between Envoy and Istio.

| Envoy                       | Target Object            | Istio                    | Target Object |
| --------------------------- | ------------------------ | ------------------------ | ------------- |
| max_connection              | cluster.circuit_breakers | maxConnection            | TcpSettings   |
| max_pending_requests        | cluster.circuit_breakers | http1MaxPendingRequests  | HttpSettings  |
| max_requests                | cluster.circuit_breakers | http2MaxRequests         | HttpSettings  |
| max_retries                 | cluster.circuit_breakers | maxRetries               | HttpSettings  |
| connection_timeout_ms       | cluster                  | connectTimeout           | TcpSettings   |
| max_requests_per_connection | cluster                  | maxRequestsPerConnection | HttpSettings  |

The Circuit Breaker used by Envoy does not adopt the traditional "Open"-"Half Open"-"Close" three-state definition, but instead, once the threshold is exceeded (or falls below), the circuit breaker will open (close).

<div align="center">
    <img src="./pics/circuit_breaker_example.png" />
</div>

Here is the example based on the figure above:

1. When the requests from the frontend service to the target service `forecast` do not exceed the configured maximum connection count, they are allowed through.
2. When the requests from the frontend service to the target service `forecast` do not exceed the configured maximum pending requests count, they enter the connection pool to wait.
3. When the requests from the frontend service to the target service `forecast` exceed the configured maximum pending requests count, they are directly rejected.

Take threshold `max_connection,` for example; if the number of active connections exceeds the threshold, it will open a circuit breaker.

`canCreateConnection` simply checks whether the number of active actions is below the cluster or per host's thresholds.

```c++
bool canCreateConnection(Upstream::ResourcePriority priority) const override {
    if (stats().cx_active_.value() >= cluster().resourceManager(priority).maxConnectionsPerHost()) {
        return false;
    }
    return cluster().resourceManager(priority).connections().canCreate();
}
```

If cannot create a new connection, the `upstream_cx_overflow_` counter in cluster traffic stats will be increased.

```c++
ConnPoolImplBase::tryCreateNewConnection(float global_preconnect_ratio) {
    const bool can_create_connection = host_->canCreateConnection(priority_);

    if (!can_create_connection) {
        host_->cluster().trafficStats()->upstream_cx_overflow_.inc();
    }

    // If we are at the connection circuit-breaker limit due to other upstreams having
    // too many open connections, and this upstream has no connections, always create one, to
    // prevent pending streams being queued to this upstream with no way to be processed.
    if (can_create_connection || (ready_clients_.empty() && busy_clients_.empty() &&
                                    connecting_clients_.empty() && early_data_clients_.empty())) {
        ENVOY_LOG(debug, "creating a new connection (connecting={})", connecting_clients_.size());
        // here are some logics for establishing a connection 
    } else {
        ENVOY_LOG(trace, "not creating a new connection: connection constrained");
        return ConnectionResult::NoConnectionRateLimited;
    }
}
```

Envoy also supports outlier detection. If an endpoint produces too many exceptions (e.g., returning 5xx HTTP status), it will be temporarily removed from the connection pool.

<div align="center">
    <img src="./pics/outlier_detection.png" />
</div>

After some time, it will be added back, but if it continues to fail, it will be removed again. Each time it's removed, the wait time to be added back increases.

So, Istio's circuit breaker has two main functionalities that involve both L4 and L7 management, as shown in the table below:

| Function                 | Network Management                                   |
| ------------------------ | ---------------------------------------------------- |
| Connection Pool Settings | L4, connection statistic, traffic control            |
| Outlier Detection        | L4 & L7, http status code statistic, traffic control |

#### Implement the connection pool settings

Here are some counters and gauges in Envoy:

+ Host Stats

    | Variable        | Type    |
    | --------------- | ------- |
    | cx_connect_fail | COUNTER |
    | cx_total        | COUNTER |
    | rq_error        | COUNTER |
    | rq_success      | COUNTER |
    | rq_timeout      | COUNTER |
    | rq_total        | COUNTER |
    | cx_active       | GAUGE   |
    | rq_active       | GAUGE   |

+ Cluster Stats

    Please check [config-cluster-manager-cluster-stats](https://www.envoyproxy.io/docs/envoy/latest/configuration/upstream/cluster_manager/cluster_stats#config-cluster-manager-cluster-stats).

We can define similar bpf map for cluster resources and cluster traffic stats. We can define some bpf maps like following:

We should record the status of each cluster, using the following data structure and bpf map:

```c
struct cluster_stats {
    __u32 active_connections;
};

struct cluster_stats_key {
    __u64 netns_cookie;
    __u32 cluster_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct cluster_stats_key));
    __uint(value_size, sizeof(struct cluster_stats));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_CLUSTER);
} map_of_cluster_stats SEC(".maps");
```

Here, the key consists of two parts: `netns_cookie` and `cluster_id`. The former is used to identify a pod, while the latter stands for a cluster. However, the identifier of cluster is its name. If we use the name as `cluster_id`, we will easily exceed the size limit of bpf stack. So, we need to map cluster name to an integer using hash:

```c
// Flush flushes the cluster to bpf map.
func (cache *ClusterCache) Flush() {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	for name, cluster := range cache.apiClusterCache {
		if cluster.GetApiStatus() == core_v2.ApiStatus_UPDATE {
			err := maps_v2.ClusterUpdate(name, cluster)
			if err == nil {
				// reset api status after successfully updated
				cluster.ApiStatus = core_v2.ApiStatus_NONE
				cluster.Id = cache.hashName.StrToNum(name)
			} else {
				log.Errorf("cluster %s %s flush failed: %v", name, cluster.ApiStatus, err)
			}
		} else if cluster.GetApiStatus() == core_v2.ApiStatus_DELETE {
			err := maps_v2.ClusterDelete(name)
			if err == nil {
				delete(cache.apiClusterCache, name)
				delete(cache.resourceHash, name)
				cache.hashName.Delete(name)
			} else {
				log.Errorf("cluster %s delete failed: %v", name, err)
			}
		}
	}
}
```
You can see that we introduce a hashName to map string to integer.

Here we also add a new field `id` to cluster:

```protobuf
message Cluster {
  enum LbPolicy {
    ROUND_ROBIN = 0;
    LEAST_REQUEST = 1;
    RANDOM = 3;
  }

  core.ApiStatus api_status = 128;
  string name = 1;
  uint32 id = 2;
  uint32 connect_timeout = 4;
  LbPolicy lb_policy = 6;

  endpoint.ClusterLoadAssignment load_assignment = 33;
  CircuitBreakers circuit_breakers = 10;
}
```

To monitor current active tcp connections, we need to create a `BPF_MAP_TYPE_SK_STORAGE` map:

```c
struct cluster_sock_data {
    __u32 cluster_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct cluster_sock_data);
} map_of_cluster_sock SEC(".maps");
```

We can manage the lifecycle of a socket based on it.

Then, we can follow the flow chart below:

<div align="center">
    <img src="./pics/kmesh_circuit_breaker_flow.png" />
</div>

We can monitor socket operations in eBPF "sockops" hooks. First, we judge whether the active connections for a cluster have reaches max thresholds. If so, we should reject the connection (how to do so is still TBD). Otherwise, we allow the connection, and handle it based on the type of socket op.

+ TCP_DEFER_CONNECT:

    We will enter sockops traffic control flow in this branch. It will trigger a series of chain calls, finally reaching `cluster_manager` (check the following image).

    <div align="center">
        <img src="./pics/kmesh_ads_mode_sockops_flow.png" />
    </div>

    We will get cluster information here (e.g, cluster id). We can store the cluster id in the `cluster_sock_data`. At this stage, we have bound the cluster to the socket.

    We can do so by calling this function below in `cluster_manager`:

    ```c
    static inline void on_cluster_sock_bind(struct bpf_sock *sk, const char* cluster_name) {
        BPF_LOG(DEBUG, KMESH, "record sock bind for cluster %s\n", cluster_name);
        struct cluster_sock_data *data = NULL;
        if (!sk) {
            BPF_LOG(WARN, KMESH, "provided sock is NULL\n");
            return;
        }

        data = bpf_sk_storage_get(&map_of_cluster_sock, sk, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (!data) {
            BPF_LOG(ERR, KMESH, "record_cluster_sock call bpf_sk_storage_get failed\n");
            return;
        }

        bpf_strncpy(data->cluster_name, BPF_DATA_MAX_LEN, (char *)cluster_name);
        BPF_LOG(DEBUG, KMESH, "record sock bind for cluster %s done\n", cluster_name);
    }
    ```

+ ACTIVE ESTABLISHED

    Here, the tcp connection has been established. We can check whether the current socket targets a cluster. If so, we should increase cluster connection counter here.

    We can call the function here:

    ```c
    static inline void on_cluster_sock_connect(struct bpf_sock_ops *ctx)
    {
        if (!ctx) {
            return;
        }
        struct cluster_sock_data *data = get_cluster_sk_data(ctx->sk);
        if (!data) {
            return;
        }
        __u64 cookie = bpf_get_netns_cookie(ctx);
        struct cluster_stats_key key = {0};
        key.netns_cookie = cookie;
        key.cluster_id = data->cluster_id;
        BPF_LOG(
            DEBUG,
            KMESH,
            "increase cluster active connections(netns_cookie = %lld, cluster id = %ld)",
            key.netns_cookie,
            key.cluster_id);
        update_cluster_active_connections(&key, 1);
        BPF_LOG(DEBUG, KMESH, "record sock connection for cluster id = %ld\n", data->cluster_id);
    }
    ```

+ TCP CLOSE

    Once the tcp connection is closed. We should decrease the counter:

    ```c
    static inline void on_cluster_sock_close(struct bpf_sock_ops *ctx)
    {
        if (!ctx) {
            return;
        }
        struct cluster_sock_data *data = get_cluster_sk_data(ctx->sk);
        if (!data) {
            return;
        }
        __u64 cookie = bpf_get_netns_cookie(ctx);
        struct cluster_stats_key key = {0};
        key.netns_cookie = cookie;
        key.cluster_id = data->cluster_id;
        update_cluster_active_connections(&key, -1);
        BPF_LOG(
            DEBUG,
            KMESH,
            "decrease cluster active connections(netns_cookie = %lld, cluster id = %ld)",
            key.netns_cookie,
            key.cluster_id);
        BPF_LOG(DEBUG, KMESH, "record sock close for cluster id = %ld", data->cluster_id);
    }
    ```

We can get the circuit breaker information from cluster data:
```c
static inline Cluster__CircuitBreakers *get_cluster_circuit_breakers(const char *cluster_name)
{
    const Cluster__Cluster *cluster = NULL;
    cluster = map_lookup_cluster(cluster_name);
    if (!cluster) {
        return NULL;
    }
    Cluster__CircuitBreakers *cbs = NULL;
    cbs = kmesh_get_ptr_val(cluster->circuit_breakers);
    if (cbs != NULL)
        BPF_LOG(DEBUG, KMESH, "get cluster's circuit breaker: max connections = %ld\n", cbs->max_connections);
    return cbs;
}
```
Then, we can get all the thresholds from `Cluster__CircuitBreakers`, and determine whether the circuit breaker should open.

#### Implement the outlier detection function

Outlier Detection in Istio and Envoy is a mechanism used to enhance the resilience and stability of microservice systems. Its primary goal is to detect and isolate instances of services that are performing abnormally, preventing these instances from affecting the overall performance and availability of the system.

It has two main functions:

+ Outlier Detection monitors the health status of service instances and identifies abnormal performance based on predefined metrics, such as the number of consecutive failed requests or the failure rate of requests.

+ Once an anomaly is detected, Outlier Detection temporarily removes the instance from the load balancing pool, effectively "ejecting" the instance to prevent it from receiving new requests. After a certain period, the system will reassess the health status of the instance and, if it has returned to normal, will reintegrate it into the load balancing pool.

We can monitor HTTP return statuses in eBPF to determine if a service is experiencing 5xx errors. When the number of such errors reaches a certain threshold, we need to exclude the corresponding endpoints from the load balancing selection.

The process of monitor and traffic management is similar to the function of connection pool settings.
