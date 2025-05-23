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

Send_bytes, receive_bytes and connection_establishment_failures are reported in the kernel.

Counts the number of connections established between a pair of IP and number of connections closed will be statistics in the user space.

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

Link Metrics：

```c
struct tcp_probe_info {
    __u32 type;
    struct bpf_sock_tuple tuple;
    __u32 sent_bytes;
    __u32 received_bytes;
    __u32 conn_success;
    __u32 direction;
    __u32 state; /* tcp state */
    __u32 protocol;
    __u64 duration; // ns
    __u64 close_ns;
    __u32 srtt_us; /* smoothed round trip time << 3 in usecs */
    __u32 rtt_min;
    __u32 mss_cache;     /* Cached effective mss, not including SACKS */
    __u32 total_retrans; /* Total retransmits for entire connection */
    __u32 segs_in;       /* RFC4898 tcpEStatsPerfSegsIn
                          * total number of segments in.
                          */
    __u32 segs_out;      /* RFC4898 tcpEStatsPerfSegsOut
                          * The total number of segments sent.
                          */
    __u32 lost_out;      /* Lost packets   */
};

// ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} map_of_tcp_info SEC(".maps");
```

![](pics/probe.svg)
