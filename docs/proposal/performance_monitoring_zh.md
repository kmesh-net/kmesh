---
title: ���ܼ���᰸
authors:
- "@skwwwwww" # Authors' GitHub accounts here.
reviewers:
- ""
- TBD
approvers:
- ""
- TBD

creation-date: 2024-09-21

---

## Kmesh �ɹ۲����᰸

<!--
This is the title of your KEP. Keep it short, simple, and descriptive. A good
title can help communicate what the KEP is and should be considered as part of
any review.
-->
### ժҪ

<!--
This section is incredibly important for producing high-quality, user-focused
documentation such as release notes or a development roadmap.

A good summary is probably at least a paragraph in length.
-->

�� Kmesh �У����ܼ����Ϊ��Ч������չ�ͽ�׳������ϵͳ�Ļ���������Ҫ����������Ҫ�ġ��� Kmesh �У���عؼ�ָ�꣬���� Kmesh �ػ����̻��eBPF map ��������ÿ�� map �е���Ŀ�����Լ� eBPF ������ִ��ʱ��������ȷ�����ϵͳ����������Ҫ��

�ڱ��᰸�У��ҽ����� Kmesh �����ܼ��ָ�ꡣ�һ��������� Kmesh ��ʵʩ��ǿ�Ŀɹ۲��Թ��ܣ��Բ�����Щ�ؼ�������ָ�ꡣ�⽫�����û��޷�ؼ�� Kmesh �����ܲ�ȷ��ϵͳЧ�ʡ�

### �᰸

Kmesh ��Ҫͨ���ں��ռ�ָ�꣬�����䴫�ݵ��û�ģʽ�����û�ģʽ�£��� eBPF map �Ͳ�������ʱ����ص��������տ���ͨ�� Prometheus ��ѯ��ʹ�� Grafana ���ӻ���

#### ���ϸ��

##### ���������ʱ����ص�ָ��

������Ϊ Kmesh ��Ҫ���ں˻�ȡָ�겢���䷢�͵��û�ģʽ��������Ҫһ�� bpf map ����¼ָ�꣬��Ϊ�����ý�顣

��ˣ�������Ҫ����һ���������б���ָ��� bpf map��

```
struct operation_usage_data {
    __u64 start_time;
    __u64 end_time;
    __u32 operation_type;
};

struct operation_usage_key {
    __u32 tid;
    __u32 operation_type;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct operation_usage_key);
    __type(value, struct operation_usage_data);
    __uint(max_entries, 1024);
} kmehs_perf_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} kmesh_perf_info SEC(".maps");
```

�ռ�������ʼ�ͽ���ʱ��ʱ��������ں�������ʱ���� map �е�����д�뻷�λ�������

##### �� ebpf map ��ص�ָ��

���û��ռ��У��� eBPF map �м��������Ϣ������ map ��������ÿ�� map �е���Ŀ����map �е������Ŀ���Լ� map �������ڴ�ռ䡣

![](pics/kmesh_map_and_operation_monitoring.jpg)

##### �� Kmesh ��Դʹ����ص�ָ��

�� cAdvisor �ṩ��ʹ�� `container_memory_usage_bytes` �� `container_cpu_usage_seconds_total` ָ�������ӻ� Kmesh ������ڴ�ʹ������� CPU ���ġ�
![](pics/kmesh_daemon_monitoring.jpg)

![](pics/performance_monitoring.jpg)

