---
title: ebpf 可观测性
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

## eBPF 可观测性

### 概要

本提案描述了如何使用 eBPF 来实现 Kmesh 的可观测信息，并重点关注访问日志和指标的设计。

### 动机

与其他服务网格数据平面一样，可观测性是网格数据平面的重要能力。Kmesh 需要提供观测方法，以帮助运维人员更好地了解当前的网络状态。

#### 非目标

NA

### 提案

如 [observability](https://github.com/kmesh-net/kmesh/blob/main/docs/proposal/observability.md) 中设计的那样，以下信息需要在 eBPF 中报告：

**访问日志：**

当连接关闭时，需要报告有关连接的以下信息：持续时间、发送的字节数 (sent_bytes)、接收的字节数 (received bytes)、连接是否成功建立以及关闭时间。

**指标：**

统计一对 IP 之间建立的连接数、关闭的连接数、发送的字节数 (sent_bytes)、接收的字节数 (received bytes) 以及连接建立失败的次数。

Send_bytes、receive_bytes 和 connection_establishment_failures 在内核中报告。

一对 IP 之间建立的连接数和关闭的连接数将在用户空间中进行统计。

### 设计细节

sk_storage：

通过 BPF_MAP_TYPE_SK_STORAGE map 存储 sock 的状态。

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
    __u32 lost_out;      /* Lost packets			*/
};

// ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} map_of_tcp_info SEC(".maps");
```

![](pics/probe.svg)
