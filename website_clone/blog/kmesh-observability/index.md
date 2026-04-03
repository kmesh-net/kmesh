---
title: "Kmesh: Metrics and Accesslog in Detail"
summary: "How kmesh uses ebpf to get traffic infos to build metrics and accesslogs."
authors:
  - LiZhenCheng9527
  - yp969803
tags: [introduce]
date: 2024-10-11T14:35:00+08:00
last_update:
  date: 2025-04-26T14:35:09+08:00
sidebar_label : "Kmesh Observability"
---

## Introduction

Kmesh is kernel native sidecarless service mesh data plane. It sinks traffic governance into the OS kernel with the help of `ebpf` and `programmable kernel`. It reduces the resource overhead and network latency of the service mesh.

And the data of the traffic can be obtained directly in the kernel and can uses `bpf map` passed to the user space. This data is used to build metrics and accesslogs.

<!-- truncate -->

## How to Get Data

In the kernel, it is possible to get the metrics data carried by the socket directly.

The data carried in the bpf_tcp_sock is as follows:

```c
struct bpf_tcp_sock {
 __u32 snd_cwnd;  /* Sending congestion window  */
 __u32 srtt_us;  /* smoothed round trip time << 3 in usecs */
 __u32 rtt_min;
 __u32 snd_ssthresh; /* Slow start size threshold  */
 __u32 rcv_nxt;  /* What we want to receive next  */
 __u32 snd_nxt;  /* Next sequence we send  */
 __u32 snd_una;  /* First byte we want an ack for */
 __u32 mss_cache; /* Cached effective mss, not including SACKS */
 __u32 ecn_flags; /* ECN status bits.   */
 __u32 rate_delivered; /* saved rate sample: packets delivered */
 __u32 rate_interval_us; /* saved rate sample: time elapsed */
 __u32 packets_out; /* Packets which are "in flight" */
 __u32 retrans_out; /* Retransmitted packets out  */
 __u32 total_retrans; /* Total retransmits for entire connection */
 __u32 segs_in;  /* RFC4898 tcpEStatsPerfSegsIn
     * total number of segments in.
     */
 __u32 data_segs_in; /* RFC4898 tcpEStatsPerfDataSegsIn
     * total number of data segments in.
     */
 __u32 segs_out;  /* RFC4898 tcpEStatsPerfSegsOut
     * The total number of segments sent.
     */
 __u32 data_segs_out; /* RFC4898 tcpEStatsPerfDataSegsOut
     * total number of data segments sent.
     */
 __u32 lost_out;  /* Lost packets   */
 __u32 sacked_out; /* SACK'd packets   */
 __u64 bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived
     * sum(delta(rcv_nxt)), or how many bytes
     * were acked.
     */
 __u64 bytes_acked; /* RFC4898 tcpEStatsAppHCThruOctetsAcked
     * sum(delta(snd_una)), or how many bytes
     * were acked.
     */
 __u32 dsack_dups; /* RFC4898 tcpEStatsStackDSACKDups
     * total number of DSACK blocks received
     */
 __u32 delivered; /* Total data packets delivered incl. rexmits */
 __u32 delivered_ce; /* Like the above but only ECE marked packets */
 __u32 icsk_retransmits; /* Number of unrecovered [RTO] timeouts */
};
```

**Notes:** The above data was not fully utilized for metrics and accesslog. Kmesh will fill in the metrics later in the development. The data used at this stage are:

```c
struct tcp_probe_info {
    __u32 type; /*type of connection (IPV4 or IPV6) */
  
    struct bpf_sock_tuple tuple;
    struct orig_dst_info orig_dst;

    __u32 sent_bytes;     /* Total send bytes from start to last_report_ns */
    __u32 received_bytes; /* Total recv bytes from start to last_report_ns */
    __u32 conn_success;
    __u32 direction;
    __u32 state;    /* tcp state */
    __u64 duration; // ns
    __u64 start_ns;
    __u64 last_report_ns; /*timestamp of the last metrics report*/
    __u32 protocol;
    __u32 srtt_us;       /* smoothed round trip time << 3 in usecs until last_report_ns */
    __u32 rtt_min;       /* min round trip time in usecs until last_report_ns */
    __u32 total_retrans; /* Total retransmits from start to last_report_ns */
    __u32 lost_out;      /* Lost packets from start to last_report_ns */
};
```

In addition to the TCP data that can be accessed directly, Kmesh temporarily records supplementary information during the connection establishment phase, such as the start time, connection direction, and the last report time. The last report time is used to periodically report connection metrics. After each report, Kmesh updates the last report time to the current timestamp, while also utilizing other stored information to enrich the reported data.

Connection stats is written to a ring buffer, allowing userspace applications to access it. Data is reported at key stages of the connection lifecycle: during connection establishment, at regular intervals throughout the connection's duration, and upon connection closure.

## How to Handle TCP stats

After parsing the data from ringbuf in the user space, Kmesh builds `metricLabels` based on the linked source and destination information. It then updates the cache in the `metricController`.

This is because the data reported through the ring buffer is connection-specific, capturing details of individual TCP connections between applications. However, the metrics exposed to the user are expected at multiple levels of granularity — including connection, pod, and service levels. As a result, aggregation of the connection data is necessary to provide meaningful metrics at the higher pod and service granularity.

Get the hostname and namespace of the destination service in the cluster from the `Services` information in the destination Workload.

```go
namespacedhost := ""
for k, portList := range dstWorkload.Services {
    for _, port := range portList.Ports {
        if port.TargetPort == uint32(dstPort) {
            namespacedhost = k
            break
        }
    }
    if namespacedhost != "" {
        break
    }
}
```

After building the metriclabels at the workload granularity, service granularity and connection granularity update the cache.

Every 5 seconds, the metrics information will be updated into Prometheus through the Prometheus API.

Access log data is generated during the processing of metrics and subsequently emitted by the daemon.

The architecture diagram is shown below:

![probe](images/probe.svg)

### Result

Metrics monitored by Kmesh L4 at this stage:

#### Workload Metrics

Give information about traffic behavior and performance between workloads.

| Name                                           | Description                                                                                    |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `kmesh_tcp_workload_connections_opened_total`  | The total number of TCP connections opened to a workload                                       |
| `kmesh_tcp_workload_connections_closed_total`  | The total number of TCP connections closed to a workload                                       |
| `kmesh_tcp_workload_received_bytes_total`      | The size of the total number of bytes received in response to a workload over a TCP connection |
| `kmesh_tcp_workload_sent_bytes_total`          | The size of the total number of bytes sent in response to a workload over a TCP connection     |
| `kmesh_tcp_workload_conntections_failed_total` | The total number of TCP connections failed to a workload                                       |
| `kmesh_tcp_retrans_total`      | Total number of retransmissions of the workload over the TCP connection |
| `kmesh_tcp_packet_loss_total`          | Total number of TCP packets lost between source and destination workload     |

Metric Result:

```bash
kmesh_tcp_workload_received_bytes_total{connection_security_policy="mutual_tls",destination_app="ws-server",destination_canonical_revision="latest",destination_canonical_service="ws-server",destination_cluster="Kubernetes",destination_pod_address="10.244.2.80",destination_pod_name="ws-server",destination_pod_namespace="default",destination_principal="-",destination_version="latest",destination_workload="ws-server",destination_workload_namespace="default",reporter="source",request_protocol="tcp",response_flags="-",source_app="ws-client",source_canonical_revision="latest",source_canonical_service="ws-client",source_cluster="Kubernetes",source_principal="-",source_version="latest",source_workload="ws-client",source_workload_namespace="default"} 6
```

#### Service Metrics

Give information about traffic behavior and performance between services.

| Name                                  | Description                                                                                   |
| ------------------------------------- | --------------------------------------------------------------------------------------------- |
| `kmesh_tcp_connections_opened_total`  | The total number of TCP connections opened to a service                                       |
| `kmesh_tcp_connections_closed_total`  | The total number of TCP connections closed to a service                                       |
| `kmesh_tcp_received_bytes_total`      | The size of the total number of bytes received in response to a service over a TCP connection |
| `kmesh_tcp_sent_bytes_total`          | The size of the total number of bytes sent in response to a service over a TCP connection     |
| `kmesh_tcp_conntections_failed_total` | The total number of TCP connections failed to a service                                       |

Metric Result:

```bash
kmesh_tcp_received_bytes_total{connection_security_policy="mutual_tls",destination_app="ws-server",destination_canonical_revision="latest",destination_canonical_service="ws-server",destination_cluster="Kubernetes",destination_principal="-",destination_service="ws-server-service.default.svc.cluster.local",destination_service_name="ws-server-service",destination_service_namespace="default",destination_version="latest",destination_workload="ws-server",destination_workload_namespace="default",reporter="source",request_protocol="tcp",response_flags="-",source_app="ws-client",source_canonical_revision="latest",source_canonical_service="ws-client",source_cluster="Kubernetes",source_principal="-",source_version="latest",source_workload="ws-client",source_workload_namespace="default"} 5
```

#### Connection Metrics

Give information about traffic behavior and performance of a established tcp connection(duration > 30 seconds). These metrics are particularly valuable in clusters running workloads that establish long-lived TCP connections, such as databases, message brokers, audio/video streaming services, AI applications etc.

| Name                                           | Description                                                                                    |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `kmesh_tcp_connection_sent_bytes_total`  | The total number of bytes sent over established TCP connection                                       |
| `kmesh_tcp_connection_received_bytes_total`  | The total number of bytes received over established TCP connection                                       |
| `kmesh_tcp_connection_packet_lost_total`      | Total number of packets lost during transmission in a TCP connection                                       |
| `kmesh_tcp_connection_retrans_total`          | The total number of retransmits over established TCP connection                                       |

Metric Result:

```bash
kmesh_tcp_connection_received_bytes_total{connection_security_policy="mutual_tls",destination_address="10.244.2.80:8080",destination_app="ws-server",destination_canonical_revision="latest",destination_canonical_service="ws-server",destination_cluster="Kubernetes",destination_pod_address="10.244.2.80",destination_pod_name="ws-server",destination_pod_namespace="default",destination_principal="-",destination_service="ws-server-service.default.svc.cluster.local",destination_service_name="ws-server-service",destination_service_namespace="default",destination_version="latest",destination_workload="ws-server",destination_workload_namespace="default",reporter="destination",request_protocol="tcp",response_flags="-",source_address="10.244.2.81:47660",source_app="ws-client",source_canonical_revision="latest",source_canonical_service="ws-client",source_cluster="Kubernetes",source_principal="-",source_version="latest",source_workload="ws-client",source_workload_namespace="default",start_time="2025-04-24 12:47:54.439318976 +0000 UTC"} 8680
```

It can also be viewed via the prometheus dashboard. Refer to [Kmesh observability](/docs/transpot-layer/l4-metrics)

Accesslog monitored by Kmesh L4 at this stage:

| Name           | Describe                                                                                                           |
| -------------- | ------------------------------------------------------------------------------------------------------------------ |
| src.addr       | Source address and port, source workload of the request                                                            |
| src.workload   | Name of the Pod that initiated the request                                                                         |
| src.namespace  | Namespace of source worklaod                                                                                       |
| dst.addr       | Destination address and port, destination workload of the request                                                  |
| dst.service    | Hostname of deatination service                                                                                    |
| dst.workload   | Name of the Pod receiving the request                                                                              |
| dst.namespace  | Namespace of destination workload                                                                                  |
| direction      | The direction of the traffic. INBOUND means into the destination service, OUTBOUND means out of the source service |
| sent_bytes     | Total bytes sent over the connection so far                    |
| received_bytes | Total bytes received over the connection so far connection                                                                       |
| duration       | Duration of this connection so far                                                                                        |
| start_time     | Start time of the connection                                  |
| packet_loss    | Total packets lost in transmission in the connection so far   |
| retransmissions | Total retransmissions in the connection so far               |
| srtt            |  Smoothed Round-Trip Time of the connection so far           |
| min_rtt         | Minimum Round-Trip Time of the connection so far             |
| state            | Current state of the connection                             |

Accesslog Result:

```bash
accesslog: 2025-04-24 08:54:40.971980208 +0000 UTC src.addr=10.244.2.79:41978, src.workload=ws-client, src.namespace=default, dst.addr=10.244.2.78:8080, dst.service=ws-server-service.default.svc.cluster.local, dst.workload=ws-server, dst.namespace=default, start_time=2025-04-24 08:53:50.919245381 +0000 UTC, direction=OUTBOUND, state=BPF_TCP_ESTABLISHED, sent_bytes=3, received_bytes=227, packet_loss=0, retransmissions=0, srtt=40515us, min_rtt=34us, duration=50052.734827ms
```

## Summary

Kmesh takes the traffic data directly from the socket and passes it as ringbuf to the user space to generate `Metric` and `Accesslog`. and expose it to Prometheus.

Avoid intercepting traffic in the user space and getting metrics in a native way. And batch update Metrics in user space at regular intervals to avoid increasing network latency during heavy traffic.

Subsequently, we will also develop the trace to complement the observability capability of kmesh.

Welcome to participate in the [Kmesh community](https://github.com/kmesh-net/kmesh)!
