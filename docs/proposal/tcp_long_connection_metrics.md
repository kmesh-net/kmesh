---
title: Proposal for generating metrics for TCP long connections
authors: 
 - "yp969803"
reviewers:
- "nglwcy"
- "lizhencheng"
approvers:
- "nlgwcy"
- "lizhencheng"

creation-date: 2025-02-06
---


## Proposal for generating metrics for TCP long connections

<!--
This is the title of your KEP. Keep it short, simple, and descriptive. A good
title can help communicate what the KEP is and should be considered as part of
any review.
-->

Upstream issue: https://github.com/kmesh-net/kmesh/issues/1211

### Summary

<!--
This section is incredibly important for producing high-quality, user-focused
documentation such as release notes or a development roadmap.

A good summary is probably at least a paragraph in length.
-->

Currently kmesh provides access logs during termination and establisment of a TCP connection with more detailed information about the connection.

Kmesh also provides metrics during connection establishment, completion and deny apturing a variety of details about the connection.

In this proposal, we are aiming to implement access logs and metrics for TCP long connections, developing a continous monitoring and reporting mechanisms that captures detailed, real-time data throughout the lifetime of long-lived TCP connections.

### Motivation

<!--
This section is for explicitly listing the motivation, goals, and non-goals of
this KEP.  Describe why the change is important and the benefits to users.
-->

Perfomance and heath of the long connections can be known early, currently we get all the information of the connection by the metrics and access logs provided at the end after the connection termination.

#### Goals

<!--
List the specific goals of the KEP. What is it trying to achieve? How will we
know that this has succeeded?
-->

- Collect detailed traffic metrics (e.g. bytes send/recieved, round-trip time, packet loss, tcp retransmission) continously during the lifetime of long TCP connections using ebpf.

- Reporting of metrics and access logs, at periodic time or based on throughput (e.g. after transfer of 1mb of data).

- User can fine tune the time and throughput using yaml during kmesh deployment or can use CLI tool kmeshctl anytime.

- Generation Access logs containing information about connection continously during the lifetime of long TCP connections from the metrics data.

- Metrics and logs supporting open-telemetry format.

- Exposing these metrics by kmesh daemon so that prometheus can scrape it.

- Unit and E2E tests.

#### Non-Goals

<!--
What is out of scope for this KEP? Listing non-goals helps to focus discussion
and make progress.
-->

- Collecting information about packet contents.

- Controlling or modifing TCP connection

- Collecting L7 metrics

### Proposal

<!--
This is where we get down to the specifics of what the proposal actually is.
This should have enough detail that reviewers can understand exactly what
you're proposing, but should not include things like API designs or
implementation. What is the desired outcome and how do we measure success?.
The "Design Details" section below is for the real
nitty-gritty.
-->

Metrics will be collected using eBPF tracepoint hooks, and a eBPF map will be used to transfer metrics from kernel space to userspace.


### Design Details

<!--
This section should contain enough information that the specifics of your
change are understandable. This may include API specs (though not always
required) or even code snippets. If there's any ambiguity about HOW your
proposal will be implemented, this is the place to discuss them.
-->

#### Collecting Metrics

We will use eBPF tracepoint hooks to collect different metrics related to connection. 
We are using tracepoint above kprobe because:
- More stable
- Lower overhead
- Reliablity in production

Storing the time-period or threshold value in the metricController

```
## Note: "---" means, previous code remains same
type MetricController struct {
  ---
  EnableTCPLongMetric   atomic.Bool
  Period                time.Duration
  Threshold             float64 ## in MBs
  IsThreshold           atomic.Bool
  ---
}
```

Currently i am only focusing on only one method, either giving metrincs of a long connection after every time interval or everytime after a specific threshold is reached(e.g. after 1mb of data has transferred).

```
func NewMetric(workloadCache cache.WorkloadCache, serviceCache cache.ServiceCache, enableMonitoring bool,enableTcpLongMetric bool ,period *time.Duration, threshold *float, isThreshold bool) *MetricController {
	m := &MetricController{
        ---
        EnableTCPLongMetric: enableTcpLongMetric
        Period:              5*time.Second,
        Threshold:           float64(1),
        IsThreshold:         isThreshold
	}

    ---

    if period != nil && *period != 0*time.Second{
      m.Period = *period
    }

    if (threshold == null && *threshold != float(0)){
        m.Threshold == *threshold
    }

	return m
}
```

The value of the period or the threshold is provided by the user, if not a default value of 5 seconds and 1 mb is chosen. If the threshold were set too low, the system might generate too many reports, leading to noise and increased processing overhead.


The labels of tcp_long_connection metric will be same as the labels we currently we have for another metrics.

#### ebpF code 

Decelearing ebpf hash map in bpf_common.h to store information about tcp_long_connection.

```
struct connection_key {
    __u32 saddr;   // Source IP address
    __u32 daddr;   // Destination IP address
    __u16 sport;   // Source port
    __u16 dport;   // Destination port
};

struct long_tcp_metrics {
    __u64 start_ns;      // Timestamp when connection was established
    __u64 bytes_sent;    // Total bytes sent
    __u64 bytes_recv;    // Total bytes received
    __u64 retransmissions;
    __u64 packet_loss;
    __u64 srtt_us;       // smoothed round-trip time in microseconds
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct connection_key);
    __type(value, struct tcp_metrics);
} long_conn_metrics_map SEC(".maps");

```

Using various ebpf tracepoints hooks to collects metrics of tcp_long_collection, a ring buffer is also decleared to send data from kernel space to userspace

Code update in tracepoint.c file
```
---

#define LONG_CONN_THRESHOLD_TIME (5 * 1000000000ULL)
#include "bpf_common.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/tcp.h>
---


// Event structure to send metrics to user space.
struct event {
    struct connection_key key;
    struct tcp_metrics metrics;
};

// BPF ring buffer to output events to user space.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB ring buffer
} tcp_long_conn_events SEC(".maps");


SEC("tracepoint/tcp/tcp_set_state")
int trace_tcp_set_state(struct trace_event_raw_tcp_set_state *ctx)
{
    struct connection_key key = {};
    u64 now = bpf_ktime_get_ns();

    key.saddr = ctx->saddr;
    key.daddr = ctx->daddr;
    key.sport = ctx->sport;
    key.dport = ctx->dport;

    if (ctx->newstate == TCP_ESTABLISHED) {
        struct tcp_metrics m = {};
        m.start_ns = now;
        bpf_map_update_elem(&conn_metrics_map, &key, &m, BPF_ANY);
    } else if (ctx->newstate == TCP_CLOSE) {
        bpf_map_delete_elem(&conn_metrics_map, &key);
    }
    return 0;
}

// Captures bytes send
SEC("tracepoint/tcp/tcp_sendmsg")
int trace_tcp_sendmsg(struct trace_event_raw_tcp_sendmsg *ctx)
{
    struct connection_key key = {};
    u64 bytes = ctx->size;
    key.saddr = ctx->saddr;
    key.daddr = ctx->daddr;
    key.sport = ctx->sport;
    key.dport = ctx->dport;
    struct tcp_metrics *m = bpf_map_lookup_elem(&conn_metrics_map, &key);
    if (m) {
        __sync_fetch_and_add(&m->bytes_sent, bytes);
    }
    return 0;
}

// Captures bytes recieved
SEC("tracepoint/tcp/tcp_cleanup_rbuf")
int trace_tcp_cleanup_rbuf(struct trace_event_raw_tcp_cleanup_rbuf *ctx)
{
    struct connection_key key = {};
    u64 bytes = ctx->copied;
    key.saddr = ctx->saddr;
    key.daddr = ctx->daddr;
    key.sport = ctx->sport;
    key.dport = ctx->dport;
    struct tcp_metrics *m = bpf_map_lookup_elem(&conn_metrics_map, &key);
    if (m) {
        __sync_fetch_and_add(&m->bytes_recv, bytes);
    }
    return 0;
}


// Track retransmissions and update RTT.
// (Assumes args->srtt_us provides the current smoothed RTT in microseconds)
TRACEPOINT_PROBE(tcp, tcp_retransmit_skb) {
    struct connection_key key = {};
    key.saddr = args->saddr;
    key.daddr = args->daddr;
    key.sport = args->sport;
    key.dport = args->dport;
    struct tcp_metrics *m = conn_metrics.lookup(&key);
    if (m) {
        __sync_fetch_and_add(&m->retransmissions, 1);
        m->srtt_us = args->srtt_us; // update latest RTT, if available
    }
    return 0;
}

// Track packet loss events.
TRACEPOINT_PROBE(tcp, tcp_drop) {
    struct connection_key key = {};
    key.saddr = args->saddr;
    key.daddr = args->daddr;
    key.sport = args->sport;
    key.dport = args->dport;
    struct tcp_metrics *m = conn_metrics.lookup(&key);
    if (m) {
        __sync_fetch_and_add(&m->packet_loss, 1);
    }
    return 0;
}



// Flush Function: Periodically invoked via a perf event.
// Iterates over the conn_metrics_map and submits events for connections
// that have been open longer than LONG_CONN_THRESHOLD_NS.
SEC("perf_event/flush")
int flush_connections(struct bpf_perf_event_data *ctx)
{
    struct connection_key key = {};
    struct connection_key next_key = {};
    struct tcp_metrics *m;
    u64 now = bpf_ktime_get_ns();
    int ret;

    // Iterate over the map. The loop is bounded by a fixed maximum (e.g., 1024 iterations)
    #pragma unroll
    for (int i = 0; i < 1024; i++) {
        ret = bpf_map_get_next_key(&conn_metrics_map, &key, &next_key);
        if (ret < 0)
            break;

        m = bpf_map_lookup_elem(&conn_metrics_map, &key);
        if (m && (now - m->start_ns >= LONG_CONN_THRESHOLD_NS)) {
            struct tcp_long_conn_events *e;
            e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->key = key;
                e->metrics = *m;
                bpf_ringbuf_submit(e, 0);
            }
        }
        key = next_key;
    }
    return 0;
}

```

#### User Stories (Optional)

<!--
Detail the things that people will be able to do if this KEP is implemented.
Include as much detail as possible so that people can understand the "how" of
the system. The goal here is to make this feel real for users without getting
bogged down.
-->

##### Story 1

##### Story 2

#### Notes/Constraints/Caveats (Optional)

<!--
What are the caveats to the proposal?
What are some important details that didn't come across above?
Go in to as much detail as necessary here.
This might be a good place to talk about core concepts and how they relate.
-->

#### Risks and Mitigations

<!--
What are the risks of this proposal, and how do we mitigate?

How will security be reviewed, and by whom?

How will UX be reviewed, and by whom?

Consider including folks who also work outside the SIG or subproject.
-->


#### Test Plan

<!--
**Note:** *Not required until targeted at a release.*

Consider the following in developing a test plan for this enhancement:
- Will there be e2e and integration tests, in addition to unit tests?
- How will it be tested in isolation vs with other components?

No need to outline all test cases, just the general strategy. Anything
that would count as tricky in the implementation, and anything particularly
challenging to test, should be called out.

-->

### Alternatives

<!--
What other approaches did you consider, and why did you rule them out? These do
not need to be as detailed as the proposal, but should include enough
information to express the idea and why it was not acceptable.
-->

<!--
Note: This is a simplified version of kubernetes enhancement proposal template.
https://github.com/kubernetes/enhancements/tree/3317d4cb548c396a430d1c1ac6625226018adf6a/keps/NNNN-kep-template
-->