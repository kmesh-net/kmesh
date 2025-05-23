---
title: map-in-map 管理增强
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

## map-in-map 管理增强

### 摘要

在 ads 模式下，支持基于 map-in-map 记录的弹性伸缩，以满足大规模集群的流量管理需求。

### 动机

正如 [optimizing_bpf_map_update_in_xDS_mode](https://github.com/kmesh-net/kmesh/blob/main/docs/proposal/optimizing_bpf_map_update_in_xDS_mode-en.md) 中提到的，为了解决 map-in-map 记录更新缓慢的问题，Kmesh 通过以空间换时间的方式在启动时一次性创建所有记录。在小规模集群场景下不会出现这个问题，但是，当支持大规模集群（例如，5000 个服务和 100,000 个 Pod）时，map-in-map 表中定义的大小非常大，并且 `BPF_MAP_TYPE_ARRAY_OF_MAPS` 类型的 map 不支持 `BPF_F_NO_PREALLOC`，这会导致大量的内存浪费。必须支持 map-in-map 记录的弹性伸缩，以满足大规模集群的流量管理需求。

#### 目标

- 支持大规模集群中的流量管理。
- 考虑配置恢复场景。

### 提案

Kmesh 在用户模式下管理 map-in-map 的使用。为了支持弹性伸缩，管理结构扩展如下：

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

Map-in-map 伸缩过程：

![map-in-map-elastic-process](pics/map-in-map-elastic-process.svg)

以下是 map-in-map 缩容和扩容的示例：

![map-in-map-elastic](pics/map-in-map-elastic.svg)
