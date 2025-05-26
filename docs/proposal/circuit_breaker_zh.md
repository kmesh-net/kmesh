---
����: Circuit Breaker
����:
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

## �� Kmesh ����� circuit breaker ����

### ����

��ҪĿ��:

+ ֧�� circuit breaker ���ơ�
+ ֧���쳣��⡣
+ ��ӳ�ֵĵ�Ԫ���ԡ�

### ����

circuit breaker ����ͨ�����ڷ�ֹ����������ɢ������ϵͳ�ȶ��ԣ����������������ϵͳ�����������ϡ���ǰ Kmesh ��δʵ�� circuit breaker ���ơ�

���� circuit breaker �ĳ�������������
+ ��������ʹ���
+ �����ӳٹ���
+ ������Դ�ľ�
+ ���񲻿���
+ ��������ﵽ�������
+ �������Ӵﵽ�������

#### Ŀ��

+ ֧�� circuit breaker ���ܣ�Kmesh Ӧ�ܴ� XDS ������ circuit breaker ���ò�������Ӧ circuit breaker��
+ ֧���쳣��⣺Kmesh Ӧ�ܴ� XDS �������쳣������ò�֧���쳣��⡣
+ ��ӳ�ֵ�Ԫ��������֤������ȷ�ԡ�

### ���ϸ��

#### Istio �е� circuit breaker ����

Envoy ֧�ּ�Ⱥ���͵���������ֵ����Ŀǰ����������ֵ�� `max_connections` �ֶο��ã�������ϸ�������[�ٷ��ĵ�](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/circuit_breaker.proto).

> per_host_thresholds
> (�ظ��� config.cluster.v3.CircuitBreakers.Thresholds)��ѡ�ĵ��������ƣ������ڼ�Ⱥ�е�ÿ��������

������ Envoy �� Istio ������ĶԱȱ�

| Envoy                       | Ŀ�����            | Istio                    | Ŀ����� |
| --------------------------- | ------------------------ | ------------------------ | ------------- |
| max_connection              | cluster.circuit_breakers | maxConnection            | TcpSettings   |
| max_pending_requests        | cluster.circuit_breakers | http1MaxPendingRequests  | HttpSettings  |
| max_requests                | cluster.circuit_breakers | http2MaxRequests         | HttpSettings  |
| max_retries                 | cluster.circuit_breakers | maxRetries               | HttpSettings  |
| connection_timeout_ms       | cluster                  | connectTimeout           | TcpSettings   |
| max_requests_per_connection | cluster                  | maxRequestsPerConnection | HttpSettings  |

Envoy ʹ�õ� circuit breaker δ���ô�ͳ�� "Open"-"Half Open"-"Close" ��̬���壬����һ������������ڣ���ֵ��circuit breaker �ͻ�򿪣��رգ���

<div align="center">
    <img src="./pics/circuit_breaker_example.png" />
</div>

������ͼ��ʾ��˵����

1. ��ǰ�˷����Ŀ�����forecast������δ�������õ����������ʱ����������ͨ����
2. ��ǰ�˷����Ŀ�����forecast������δ�������õ�������������ʱ������������ӳصȴ���
3. ��ǰ�˷����Ŀ�����forecast�����󳬹����õ�������������ʱ������ֱ�ӱ��ܾ���

����ֵ `max_connection,` Ϊ�������������������ֵʱ��circuit breaker ���򿪡�

`canCreateConnection` ����������������Ƿ���ڼ�Ⱥ����������ֵ��

```c++
bool canCreateConnection(Upstream::ResourcePriority priority) const override {
    if (stats().cx_active_.value() >= cluster().resourceManager(priority).maxConnectionsPerHost()) {
        return false;
    }
    return cluster().resourceManager(priority).connections().canCreate();
}
```

���޷����������ӣ���Ⱥ����ͳ���е� `upstream_cx_overflow_` �����������ӣ�

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

Envoy ��֧���쳣��⣺��ĳ���˵���������쳣���緵�� 5xx HTTP ״̬�룩���ᱻ��ʱ�����ӳ����Ƴ���

<div align="center">
    <img src="./pics/outlier_detection.png" />
</div>

һ��ʱ���ö˵�ᱻ���¼��룬���������ʧ������ٴα��Ƴ�����ÿ���Ƴ���ĵȴ�ʱ��������

��ˣ�Istio �Ķ�·������ L4 �� L7 ������������Ĺ��ܣ����±���ʾ��


| ����                 | �������                                   |
| ------------------------ | ---------------------------------------------------- |
| ���ӳ����� | L4 �㣬����ͳ������������            |
| �쳣���        | L4 & L7 �㣬HTTP ״̬��ͳ������������ |

#### ʵ�����ӳ�����

������ Envoy �е�һЩ�������ͼ�����

+ ����ͳ��

    | ����        | ����    |
    | --------------- | ------- |
    | cx_connect_fail | COUNTER |
    | cx_total        | COUNTER |
    | rq_error        | COUNTER |
    | rq_success      | COUNTER |
    | rq_timeout      | COUNTER |
    | rq_total        | COUNTER |
    | cx_active       | GAUGE   |
    | rq_active       | GAUGE   |

+ ��Ⱥͳ��

    ����� [config-cluster-manager-cluster-stats](https://www.envoyproxy.io/docs/envoy/latest/configuration/upstream/cluster_manager/cluster_stats#config-cluster-manager-cluster-stats).

���ǿ���Ϊ��Ⱥ��Դ�ͼ�Ⱥ����ͳ����Ϣ�������Ƶ� bpf ӳ�䡣���ǿ��Զ���һЩ bpf ӳ�䣬������ʾ��

����Ӧ��ʹ���������ݽṹ�� bpf ӳ���¼ÿ����Ⱥ��״̬��

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
�����������������ɣ� `netns_cookie` �� `cluster_id`��ǰ�����ڱ�ʶ Pod�������ߴ���Ⱥ�����ǣ�cluster �ı�ʶ���������ơ��������ʹ������Ϊ `cluster_id`�����Ǻ����׳��� bpf ��ջ�Ĵ�С���ơ���ˣ�������Ҫʹ�� hash �� cluster name ӳ�䵽һ��������

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
����Կ�������������һ�� hashName �����ַ���ӳ�䵽������

��������ǻ��� cluster �����һ�����ֶ� `id`��

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
Ҫ��ص�ǰ��Ծ�� tcp ���ӣ�������Ҫ����һ�� `BPF_MAP_TYPE_SK_STORAGE` ӳ�䣺

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

���ǿ��Ի����������� socket ���������ڡ�

Ȼ�����ǿ��԰������������ͼ��������

<div align="center">
    <img src="./pics/kmesh_circuit_breaker_flow.png" />
</div>

���ǿ��Լ�� eBPF ��sockops�� hooks �е� socket�������ȣ������жϼ�Ⱥ�Ļ�Ծ�������Ƿ�ﵽ�����ֵ�����������������Ӧ�þܾ������ӣ����������һ����Ȼ�����������������������ӣ������� socket op �����ͽ��д���

+ TCP_DEFER_CONNECT:

    ���ǽ��ڴ˷�֧������ sockops ��������������������һϵ����ʽ���ã����մﵽ`cluster_manager`  ���鿴��ͼ����

    <div align="center">
        <img src="./pics/kmesh_ads_mode_sockops_flow.png" width="50%" />
    </div>

    ���ǽ��ڴ˴���ȡ��Ⱥ��Ϣ�����磬��Ⱥ ID�������ǿ��Խ���Ⱥ ID �洢��`cluster_sock_data` �С�������׶Σ������Ѿ�����Ⱥ�󶨵� socket��

    ���ǿ���ͨ��������� `cluster_manager` �е������������ʵ����һ�㣺

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

    �����TCP �����ѽ��������ǿ��Լ�鵱ǰ socket �Ƿ�ָ��Ⱥ������ǣ�����Ӧ�����������Ӽ�Ⱥ���Ӽ�������

    ���ǿ�������������������:

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

    һ�� TCP ���ӹرգ�����Ӧ�ü��ټ�����:

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

���ǿ��ԴӼ�Ⱥ�����л�ȡ circuit breaker ��Ϣ��
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
Ȼ�����ǿ��Դ� `Cluster__CircuitBreakers` ��ȡ������ֵ����ȷ�� circuit breaker �Ƿ�Ӧ�ô򿪡�

#### ʵ���쳣ֵ��⺯��

Istio �� Envoy �е��쳣�����һ����ǿ΢����ϵͳ���Ժ��ȶ��ԵĻ��ơ�����ҪĿ���Ǽ��͸�������쳣�ķ���ʵ������ֹ��Щʵ��Ӱ��ϵͳ���������ܺͿ����ԡ�

����������Ҫ���ܣ�

+ �쳣����ط���ʵ���Ľ���״̬��������Ԥ����Ķ�����׼ʶ���쳣���ܣ���������ʧ������������������ʧ���ʡ�

+ һ����⵽�쳣���쳣������ʱ����ʵ���Ӹ��ؾ�������Ƴ�����Ч�ء����𡱸�ʵ���Է�������µ����󡣾���һ��ʱ���ϵͳ������������ʵ���Ľ���״̬��������Ѿ��ָ����������Ὣ���������븺�ؾ���ء�

���ǿ����� eBPF �м�� HTTP ����״̬����ȷ�������Ƿ���� 5xx ���󡣵��������������ﵽĳ����ֵʱ��������Ҫ����Ӧ�Ķ˵��ų��ڸ��ؾ���ѡ��֮�⡣

��غ���������Ĺ������������ӳ����õĹ��ܡ�
