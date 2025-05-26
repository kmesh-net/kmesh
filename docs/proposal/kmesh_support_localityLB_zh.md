---
title: Kmesh �ı����Ը��ؾ���
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

## Kmesh �ı����Ը��ؾ���

### ժҪ

Ϊ Kmesh ��������ģʽ��ӱ����Ը��ؾ��⡣

### ����

Ŀǰ��Kmesh ��֧�ֱ����Ը�֪���ؾ��⡣�����Ը��ؾ���ͨ����������������ķ���ʵ�����Ż��ֲ�ʽϵͳ�е����ܺͿɿ��ԡ����ַ����������ӳ٣�����˿����ԣ�������������������ݴ�����صĳɱ�������ȷ���˷���������Ȩ���棬��ͨ���ṩ���졢���ɿ��ķ�����Ӧ�����������û����顣

### Ŀ��

���᰸��Ŀ����Ϊ kmesh ��������ģʽ��ӱ����Ը�֪���ؾ�����������Ӧ�� istio ambient mesh �еı����Ը��ؾ��⡣

### �᰸

�����Ը��ؾ���ģʽ�������Թ���ת�ƣ��������ϸ�

ʲô�Ǳ����Թ���ת��ģʽ����������ʷ���ʱ������ƽ�潫��������Դ pod �ı�������Ϣ����񱳺����н�����˵ı����Խ��зֲ�ƥ�䡣ƥ��ȸ��ߵ� Pod ��ʾ�����ڵ���λ���ϸ��ӽ�������������·�ɵ�ƥ��ȸ��ߵ� Pod��

ʲô�Ǳ������ϸ�ģʽ���ڱ������ϸ�ģʽ�£�LB�����ؾ��⣩�㷨����ѡ���� routingPreference ��ȫƥ��ĺ�ˡ�����ζ��������ģʽ�£����ؾ�������ǿ��ִ���ϸ�Ĳ��ԣ���������ָ��������ƫ�õ���ȫƥ�佫����·�ɵ���ˣ��Ӷ�ȷ����������������λ�û�����������ص��ض���׼�ķ���������

### ���ϸ��

1. �� BPF ��� `service_manager` ��ʵ���µĸ��ؾ��⴦���߼���`lb_locality_failover_handle`��
2. �� BPF ������ݽṹ����˸����Ҫ����Ϣ��map `service_value` �洢���ؾ������ `lb_policy` ��һ������ `prio_endpoint_count[PRIO_COUNT]`�����ڼ��㲻ͬ���ȼ��Ķ˵㡣map `endpoint_key` �洢��ǰ�˵�����ȼ� `prio`��
3. ���û��������һ�� `locality_cache` ģ�飬���ڴ洢�����Ը�֪��Ϣ�����ȼ������߼���
4. �������û���� `ServiceValue` �� `EndpointKey` map��
5. ����ͨ������ `EndpointKey` ��̬ά���벻ͬ���ȼ���Ӧ�Ķ˵㡣Ϊ���ڸ��²���ʱ���� `EndpointKey`�����������һ�� `endpoint_cache` ���洢����Ķ˵���Ϣ��
6. �� `workload_processor` �У����Ǹ�������Ӻ�ɾ���˵�ͷ�����߼����Լ��ڴ��������غͷ��� xDs ��Ϣʱ������Ӧ map ��Ϣ���߼��������� `handleWorkloadUnboundServices` ��ʵ���� LB �����߼���Ϊ��ȷ������������ԣ����ǿ����˲����л��ڼ�ĳ���������һʵ���� `endpointKey` ���¡�
7. ����������ԣ����ж˵㶼���Ϊ���ȼ� 0�����ڹ���ת�ƻ��ϸ���ԣ����� `routingPreference`�����ȼ�����Ϊ�����ƥ��Ķ˵�Ϊ 0��

#### ������
<div style="text-align:center"><img src="pics/locality_lb.svg" /></div>

#### ���ݽṹ
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
