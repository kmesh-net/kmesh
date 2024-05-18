---
title: Optimizing bpf map update in xDS mode
authors:
- "@nlgwcy"
reviewers:
- "@robot"
- "@hzxuzhonghu"
- "@supercharge-xsy"
- "@bitcoffeeiux"
approvers:
- "@robot"
- TBD

creation-date: 2024-05-13

---

## Optimizing bpf map update in xDS mode

### Summary

Kmesh is a grid-based data plane governance forwarding system implemented with eBPF. After xDS configurations are distributed to Kmesh-daemon, they are deserialized using a library and then updated as eBPF maps in the kernel. However, the update performance is poor. This proposal introduces optimization strategies to address this issue. 

### Motivation

During xDS configuration updates, the performance of eBPF map refresh is poor, resulting in delayed responsiveness to xDS changes notified by Istiod. For example, the time taken for a single routeconfig update is in the order of seconds. Performance analysis profiling revealed that the add and delete operations on the outter_map table (ARRAY_OF_MAPS) are relatively slow, with measured time cost of approximately 5ms for each record addition or deletion. The main reason for this is the synchronous operations involved in the add and delete processes of this type of map.

[Unit testing](https://github.com/kmesh-net/kmesh/blob/1ae49ce4b623bc888ad2386d9acbc531d6c62d67/pkg/cache/v2/cluster_test.go#L180) eBPF map refresh latency:

```sh
[root@localhost v2]# go test -bench=. --benchtime=100x
goos: linux
goarch: amd64
pkg: kmesh.net/kmesh/pkg/cache/v2
cpu: Intel(R) Xeon(R) CPU E5-2690 v3 @ 2.60GHz
BenchmarkClusterFlush-16             100         835615271 ns/op
BenchmarkFlush-16                    100        1595920212 ns/op
PASS
ok      kmesh.net/kmesh/pkg/cache/v2    245.370s
[root@localhost v2]#
```

#### Goals

The latency of a single xDS configuration update is in the millisecond range.

### Proposal

#### eBPF map update mechanism

In the xDS model, configurations are organized hierarchically. The current design achieves map hierarchy through the map-in-map mechanism of eBPF maps. The specific implementation is as follows: 

- xDS model -> proto-c data struct

  ![](pics/kmesh-proto.svg)

- Organized through map-in-map

  ![](pics/kmesh-map-in-map.svg)

  For the value member of map records, if it is a pointer variable involving referencing other data structures, the actual data area is stored in the inner-map:

  - If the value member is a primitive data type (such as int), it can be accessed directly.
  - If the value member is a pointer type, the value stored in the pointer is the index of the inner-map that holds the actual data in the outter_map table (note: the index is updated when writing to the bpf map in the xds-adapter module of kmesh-daemon). When accessing, the inner-map's map fd is first retrieved based on the index, then the actual data is fetched from the inner-map table. For multi-level pointer members, this process is repeated until all pointer information is stripped away.

  The benefits of this design are:

  - xDS model changes do not require redefining eBPF map data structures, providing high flexibility.

#### Optimization solution

The current implementation scheme is as follows:

- Bitmap is used to manage which inner_map records are free, and the bitmap information is stored in the first record of the outter_map.
- During xDS configuration creation, the outter_map is searched for a `idle`idx, and the corresponding inner_map is created. The inner_map information is added to the outter_map table, and the bitmap information is updated as `used`(the outter_map table is also updated).
- During xDS configuration deletion, the idx recorded in the outter_map is searched for, and the corresponding inner_map table is deleted. The record in the outter_map is also removed, and the bitmap information is updated as `idle`.

As we can see, one xDS change involves multiple outter_map refreshes. Here is the optimization approach (space-time trade-off):

- When kmesh-daemon starts, create all outter_map records (including inner_map) at once, using multiple threads to parallelize the refresh process since the outter_map table updates slowly.
- Maintain an `inner_map_mng` table in memory, which keeps track of the idle status of each idx and its corresponding inner_map.
- During xDS configuration creation, for pointer/string members, retrieve an `idle` idx record from inner_map_mng and update the actual content into the inner_map table associated with that idx. Also, update the status of that record as `used`.
- During xDS configuration deletion, find the record corresponding to the idx in `inner_map_mng` and update its status as `idle`.

![](pics/kmesh-map-in-map-optimization.svg)

#### Risks and Mitigations

This approach utilizes a space-time trade-off. When the size of the outter_map table is set to be relatively large, it is not suitable to create all inner_map records at once, as it may lead to a longer startup time for kmesh-daemon and excessive memory consumption. Here are some potential optimization strategies:

- During kmesh-daemon initialization, only create outter_map records of a specific size and then start a background thread to gradually create the remaining records.
- Create outter_map records on demand based on actual usage scenarios.

#### Test

Performance test results of the optimization strategy：

```sh
[root@localhost v2]# go test -bench=. --benchtime=100x
goos: linux
goarch: amd64
pkg: kmesh.net/kmesh/pkg/cache/v2
cpu: Intel(R) Xeon(R) CPU E5-2690 v3 @ 2.60GHz
BenchmarkClusterFlush-16             100            600145 ns/op
BenchmarkFlush-16                    100            283194 ns/op
PASS
ok      kmesh.net/kmesh/pkg/cache/v2    4.047s
```



