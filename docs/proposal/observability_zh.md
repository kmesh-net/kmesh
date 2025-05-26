---
title: Kmesh �ɹ۲����᰸
authors:
- "@LiZhencheng9527" # �˴���д���ߵ� GitHub �˺�
reviewers:
- ""
- TBD
approvers:
- ""
- TBD

creation-date: 2024-05-16

---

## Kmesh �ɹ۲����᰸

<!--
������� KEP �ı��⡣���ּ�̡��򵥺������ԡ�һ���õı�����԰�����ͨ KEP �����ݣ�Ӧ�ñ���Ϊ�κ�����һ���֡�
-->

### ժҪ

<!--
���ڶ������ɸ����������û�Ϊ���ĵ��ĵ����緢��˵���򿪷�·��ͼ��������Ҫ��

һ���õ�ժҪ����������һ������ĳ��ȡ�
-->

��������Ŀɹ۲��Ե���Ҫ����Ϊ�ɹ�����ɿ��Ϳɳ�������ϵͳ�Ļ������ݺ��ӡ��� istio �У��� l4 �� l7 ���ṩ�� accesslog��ָ���׷�٣��������û��Կɹ۲��Ե�����

�ڱ��᰸�У��ҽ����� istio �Ŀɹ۲���ָ�ꡣ������ Kmesh ʵ�ֿɹ۲��Թ�����֧����Щָ�ꡣ�Ա��û������޷�ʹ�� Kmesh��

### ����

<!--
����������ȷ�г��� KEP �Ķ�����Ŀ��ͷ�Ŀ�ꡣ����Ϊʲô�˸��ĺ���Ҫ�Լ����û��ĺô���
-->

#### Accesslog

�� [istio ztunnel](https://github.com/istio/ztunnel?tab=readme-ov-file#logging) �У��� 4 �������־��������ָ�꣺

source.addr
source.workload
source.namespace
source.identity

destination.addr
destination.hbone_addr
destination.service
destination.workload
destination.namespace
destination.identity

direction

bytes_sent
bytes_recv
duration

������ʾ�˻�õ� accesslog ��ʾ����

```console
2024-05-30T12:18:10.172761Z	info access	connection complete
    src.addr=10.244.0.10:47667 src.workload=sleep-7656cf8794-9v2gv src.namespace=ambient-demo src.identity="spiffe://cluster.local/ns/ambient-demo/sa/sleep" 
    dst.addr=10.244.0.7:8080 dst.hbone_addr=10.244.0.7:8080 dst.service=httpbin.ambient-demo.svc.cluster.local dst.workload=httpbin-86b8ffc5ff-bhvxx dst.namespace=ambient-demo 
    dst.identity="spiffe://cluster.local/ns/ambient-demo/sa/httpbin" 
    direction="inbound" bytes_sent=239 bytes_recv=76 duration="2ms"
```

accesslog ��Ҫ����Ŀ���Դ����ݣ���ַ/��������/�����ռ�/��ݣ������⣬�����ָ���Ƿ��͵���Ϣ��С (bytes_sent)�����յ���Ϣ��С (bytes_recv) �����ӵĳ���ʱ�䡣

Ϊ�����û��ܹ�˳��ʹ�� Kmesh��Kmesh ��Ҫ֧����Щ accesslog��

#### ָ��

Ϊ�˼�ط�����Ϊ��Istio ��Ϊ���� Istio ���������Լ��� Istio ���������ڵ����з�����������ָ�ꡣ��Щָ���ṩ�й���Ϊ����Ϣ��

�ο� [istio ztunnel metric](https://github.com/istio/ztunnel/blob/6532c553946856b4acc326f3b9ca6cc6abc718d0/src/proxy/metrics.rs#L369) ���ڵ� L4 �㣬�����ָ���ǣ�

```console
connection_opens: �򿪵� TCP ��������
connection_close: �رյ� TCP ��������
received_bytes: TCP ��������������ڼ���յ����ֽ�����С
sent_bytes: TCP �����������Ӧ�ڼ䷢�͵����ֽ�����С
on_demand_dns: ʹ�ð��� DNS ���������������ȶ���
on_demand_dns_cache_misses: ���� DNS ����Ļ���δ�������������ȶ���
```

����ָ������ DNS ��ص�ָ�꣬���� Kmesh ��δ֧�� DNS�����ǽ��� Kmesh DNS ����ʵ�ֺ���֧������

��ˣ�Kmesh ������Ҫ֧�� `connection_opens`��`connection_close`��`received_bytes`��`sent_bytes`��

����ָ�껹����������ʾ�ı�ǩ��

```console
reporter

source_workload
source_canonical_service
source_canonical_revision
source_workload_namespace
source_principal
source_app
source_version
source_cluster

destination_service
destination_service_namespace
destination_service_name

destination_workload
destination_canonical_service
destination_canonical_revision
destination_workload_namespace
destination_principal
destination_app
destination_version
destination_cluster

request_protocol
response_flag
connection_security_policy

istio_tcp_sent_bytes_total{
    reporter="destination",

    source_workload="sleep",source_canonical_service="sleep",source_canonical_revision="latest",source_workload_namespace="ambient-demo",
    source_principal="spiffe://cluster.local/ns/ambient-demo/sa/sleep",source_app="sleep",source_version="latest",source_cluster="Kubernetes",
    
    destination_service="tcp-echo.ambient-demo.svc.cluster.local",destination_service_namespace="ambient-demo",destination_service_name="tcp-echo",destination_workload="tcp-echo",destination_canonical_service="tcp-echo",destination_canonical_revision="v1",destination_workload_namespace="ambient-demo",
    destination_principal="spiffe://cluster.local/ns/ambient-demo/sa/default",destination_app="tcp-echo",destination_version="v1",destination_cluster="Kubernetes",
    
    request_protocol="tcp",response_flags="-",connection_security_policy="mutual_tls"} 16
```

`Report` ��ʾָ�����ڷ��ͷ����ǽ��շ���Ȼ���ǹ���Դ��Ŀ���һЩ�����Ϣ����Щ������ accesslog �еı�ǩ��

Ȼ���� `request_protocol`��`response_flag` �� `connection_security_policy`��`connection_security_policy` ��ֵ�� mutual_tls �� unknown��

���� istio �Ѿ����õ�ָ��֮�⣬���� Kmesh �ܹ����ں˻��[���ḻ��ָ��](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#tcp%E6%8C%87%E6%A0%87)���⽫�� Kmesh �����ơ�

#### Ŀ��

<!--
�г� KEP �ľ���Ŀ�ꡣ����ͼʵ��ʲô���������֪�����Ѿ��ɹ���
-->

���ں������Ϊ����ǿ Kmesh �Ŀɹ۲��ԣ�������Ҫ��

- �� ebpf ��ȡ�����ָ�ꡣ
- �ӻ�ȡ���������� accesslog
- ֧��ͨ�� Prometheus ��ѯָ��

#### ��Ŀ��

<!--
�� KEP �ķ�Χ֮����ʲô���г���Ŀ�������ڼ������۲�ȡ�ý�չ��
-->

- �� Dns ��ص�ָ�ꡣ
- L7 ���ָ�ꡣ

### �᰸

<!--
��������ǽ������˽��᰸�ľ������ݡ���Ӧ�����㹻��ϸ�ڣ��Ա������߿���׼ȷ���������������ݣ�����Ӧ���� API ��ƻ�ʵ��֮������ݡ�ʲô�������Ľ����������κ����ɹ�������ġ����ϸ�ڡ���������������ϸ�ڡ�
-->

Kmesh ��Ҫͨ���ں��ռ�ָ�겢�����Ǵ��ݵ��û�ģʽ�����û�ģʽ�£�accesslog ��ָ�����ɡ���֧��ͨ�� kemsh localhost:15020 ��ѯָ�ꡣ

### ���ϸ��

<!--
����Ӧ�����㹻����Ϣ���Ա����������ĸ��ĵľ���ϸ�ڡ�����ܰ��� API �淶�����ܲ������Ǳ���ģ���������Ƭ�Ρ�����������᰸�����ʵʩ���κ����壬������ڴ˴��������ۡ�
-->

������Ϊ Kmesh ��Ҫ���ں˻�ȡָ�겢�����Ƿ��͵��û�ģʽ��������Ҫһ�� bpf map ����¼ָ�꣬��Ϊ�����ý�顣

��ˣ�������Ҫ����һ���������б���ָ��� bpf map��

```console
struct conn_value {
  u64 connection_opens;
  u64 connection_closes;
  u64 received_bytes;
  u64 sent_bytes;
  u64 duration;

  __u32 destination; 
  __u32 source;
};
```

�����Ŀ���Դ�ǰ����������������Ϣ�� bpf map��

#### ������־

�� TCP ������ֹʱ��ebpf ͨ�� bpf map ���������е����ݷ��͵� kmesh-daemon��

�������������� accesslog��Ȼ���� kmesh log ��ӡ��

#### ָ��

ָ��Ļ�ȡ��ʽ�� accesslog ��ͬ��

ͨ�� bpf map ��ȡָ������ǻ�����֧�� Prometheus ��ѯ��

1. ��ָ�깫���� Prometheus Registry ���� HTTP �����ӿڡ�
2. ���� HTTP �����ӿڡ�
3. ���ڸ���ָ�ꡣÿ�����ӶϿ�ʱ����ָ�ꡣ

<div align="center">
<img src="pics/observability.svg" width="800" />
</div>

�ɹ۲���Ӧ�� ads ģʽ�͹�������ģʽ��ʵ�֡�

��������ֻ����ʵ�� l4 ��Ŀɹ۲��ԡ�

����ָ�깦�ܣ��ṩ 15020 �˿����� Prometheus ��ѯ��

#### ���Լƻ�

<!--
**ע�⣺** *����Է����汾֮ǰ����Ҫ��*

��Ϊ����ǿ�����ƶ����Լƻ�ʱ���뿼���������
- ���˵�Ԫ����֮�⣬�Ƿ���� e2e �ͼ��ɲ��ԣ�
- ����ڸ���״̬���Լ����������һ����в��ԣ�

����������в���������ֻ�����������Լ��ɡ��κ���ʵ�����������ֵ����飬�Լ��κ��ر������ս�ԵĲ��ԣ���Ӧ����˵����

-->

### �������

<!--
������������Щ�����������Լ�Ϊʲô���ų������ǣ���Щ����Ҫ���᰸������ϸ����Ӧ�����㹻����Ϣ�������뷨�Լ�Ϊʲô�����ɽ��ܡ�
-->

<!--
ע�⣺���� kubernetes ��ǿ�᰸ģ��ļ򻯰汾��
https://github.com/kubernetes/enhancements/tree/3317d4cb548c396a430d1c1ac6625226018adf6a/keps/NNNN-kep-template
-->

