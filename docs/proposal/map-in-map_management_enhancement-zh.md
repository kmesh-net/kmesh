---
title: map-in-map ������ǿ
authors:
- "@nlgwcy"
reviewers:
- "@hzxuzhonghu"
- "@supercharge-xsy"
- "@bitcoffeeiux"
approvers:
- "@robot"
- TBD

creation-date: 2024-07-20

---

## map-in-map ������ǿ

### ժҪ

�� ads ģʽ�£�֧�ֻ��� map-in-map ��¼�ĵ�����������������ģ��Ⱥ��������������

### ����

���� [optimizing_bpf_map_update_in_xDS_mode](https://github.com/kmesh-net/kmesh/blob/main/docs/proposal/optimizing_bpf_map_update_in_xDS_mode-en.md) ���ᵽ�ģ�Ϊ�˽�� map-in-map ��¼���»��������⣬Kmesh ͨ���Կռ任ʱ��ķ�ʽ�����ʱһ���Դ������м�¼����С��ģ��Ⱥ�����²������������⣬���ǣ���֧�ִ��ģ��Ⱥ�����磬5000 ������� 100,000 �� Pod��ʱ��map-in-map ���ж���Ĵ�С�ǳ��󣬲��� `BPF_MAP_TYPE_ARRAY_OF_MAPS` ���͵� map ��֧�� `BPF_F_NO_PREALLOC`����ᵼ�´������ڴ��˷ѡ�����֧�� map-in-map ��¼�ĵ�����������������ģ��Ⱥ��������������

#### Ŀ��

- ֧�ִ��ģ��Ⱥ�е����������
- �������ûָ�������

### �᰸

Kmesh ���û�ģʽ�¹��� map-in-map ��ʹ�á�Ϊ��֧�ֵ�������������ṹ��չ���£�

```c
struct inner_map_mng {
    int inner_fd;
    int outter_fd;
    struct bpf_map_info inner_info;
    struct bpf_map_info outter_info;
    struct inner_map_stat inner_maps[MAX_OUTTER_MAP_ENTRIES];
    int elastic_slots[OUTTER_MAP_ELASTIC_SIZE];
    int used_cnt;           // real used count
    int alloced_cnt;        // real alloced count
    int max_alloced_idx;    // max alloced index, there may be holes.
    int init;
    sem_t fin_tasks;
    int elastic_task_exit;  // elastic scaling thread exit flag
};

struct inner_map_stat {
    int map_fd;
    unsigned int used : 1;
    unsigned int alloced : 1;
    unsigned int resv : 30;
};
```

Map-in-map �������̣�

![map-in-map-elastic-process](pics/map-in-map-elastic-process.svg)

������ map-in-map ���ݺ����ݵ�ʾ����

![map-in-map-elastic](pics/map-in-map-elastic.svg)

