---
title: ebpf observability
authors:
- "@nlgwcy"
reviewers:
- "@bitcoffeeiux"
- "@hzxuzhonghu"
- "@supercharge-xsy"
approvers:
- "@robot"

creation-date: 2024-06-28


---

## eBPF Observability

### Summary

This proposal describes how to use the eBPF to implement observable information of Kmesh, and focuses on the design of access logs and metrics.

### Motivation

Like other service mesh data planes, observability is an important ability of the mesh data plane. Kmesh needs to provide observation methods to help O&M personnel better understand the current network status.

#### Non-Goals

NA

### Proposal

As designed in [observability](https://github.com/kmesh-net/kmesh/blob/main/docs/proposal/observability.md), the following information needs to be reported in eBPF:

**access logs:**

When a connection is closed, the following information about the connection need reported: duration, sent_bytes, received bytes, whether the connection is set up successfully, and the close time.

**metrics:**

Counts the number of connections established between a pair of IP, number of connections closed, sent_bytes, received bytes, and number of connection establishment failures.

### Design Details

sk_storage：

Storage the status of sock by BPF_MAP_TYPE_SK_STORAGE map.

```c
struct sock_storage_data {
    __u64 connect_ns;
    __u8 direction;
    __u8 connect_success;
};
```

access log：

```c
struct tcp_probe_info {
    struct bpf_sock_tuple tuple;
    __u64 duration; // ns
    __u64 close_ns;
    __u32 family;
    __u32 protocol;
    __u8 direction;
    __u32 sent_bytes;
    __u32 received_bytes;
    __u32 conn_success;
};

// ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} map_of_tcp_info SEC(".maps");
```

metrics:

```c
// key:
struct metric_key {
    struct ip_addr src_ip;
    struct ip_addr dst_ip;
};

// value:
struct metric_data {
    __u8 direction;       // update on connect
    __u32 conn_open;      // update on connect
    __u32 conn_close;     // update on close
    __u32 conn_failed;    // update on close
    __u32 sent_bytes;     // update on close
    __u32 received_bytes; // update on close
};

#define MAP_SIZE_OF_METRICS 100000
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct metric_key);
    __type(value, struct metric_data);
    __uint(max_entries, MAP_SIZE_OF_METRICS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_of_metrics SEC(".maps");
```

![](pics/probe.svg)
