---
title: map-in-map management enhancement
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

## map-in-map management enhancement

### Summary

In ads mode, elastic scaling based on map-in-map records is supported to meet the traffic management requirements of large-scale clusters.

### Motivation

As mentioned in [optimizing_bpf_map_update_in_xDS_mode](https://github.com/kmesh-net/kmesh/blob/main/docs/proposal/optimizing_bpf_map_update_in_xDS_mode-en.md), to solve the problem of slow update of map-in-map records, Kmesh creates all records at a time during startup by exchanging space for time. This problem does not occur in small-scale cluster scenarios, however, when a large-scale cluster (for example, 5000 services and 100,000 pods) is supported, the size defined in the map-in-map table is very large, and the map of the `BPF_MAP_TYPE_ARRAY_OF_MAPS` type does not support `BPF_F_NO_PREALLOC`, which causes a great waste of memory. Elastic scaling of map-in-map records must be supported to meet the traffic management requirements of large-scale clusters.

#### Goals

- Supports traffic management in large-scale clusters.
- Consider the configuration restoration scenario.

### Proposal

Kmesh manages the usage of map-in-map in user mode. To support elastic scaling, the management structure is extended as follows:

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

Map-in-map scaling process:

![map-in-map-elastic-process](pics/map-in-map-elastic-process.svg)

The following is an example of map-in-map scale-in and scale-out:

![map-in-map-elastic](pics/map-in-map-elastic.svg)
