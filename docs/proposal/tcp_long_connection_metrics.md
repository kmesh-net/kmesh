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

Currently kmesh provides access logs during termination and establisment of a TCP connection with more detailed information about the connection, such as bytes sent, received, packet lost, rtt and retransmits.

Kmesh also provides workload and service specific metrics such as bytes sent and received, lost packets, minimum rtt, total connection opened and closed by a pod, These metrics are only updated after a connection is closed. In this proposal we are aiming to update these metrics periodically.

We are also aiming to implement access logs and metrics for TCP long connections, developing a continuous monitoring and reporting mechanisms that captures detailed, real-time data throughout the lifetime of long-lived TCP connections. Access logs are reported periodically with information such as reporting time, connection establishment time, bytes sent, received, packet losts, rtt, retransmits and state. Metrics such as bytes sent and received, packet losts, retransmits is also reported periodically for long connections.

### Motivation

<!--
This section is for explicitly listing the motivation, goals, and non-goals of
this KEP.  Describe why the change is important and the benefits to users.
-->

Performance and heath of the long connections can be known early, currently we get all the information of the connection by the metrics and access logs provided at the end after the connection termination.

#### Goals

<!--
List the specific goals of the KEP. What is it trying to achieve? How will we
know that this has succeeded?
-->
- Reporting workload and service based metrics periodically(5 sec).

- Collect detailed traffic metrics (e.g. bytes send/received, round-trip time, packet loss, tcp retransmission) continuously during the lifetime of long TCP connections using ebpf.

- Reporting of metrics and access logs, at periodic time of 5 seconds. We are choosing 5 seconds as a threshold time because, it allows enough time to accumulate meaningful changes in metrics. If the reporting interval is too short, it might cause excessive overhead by processing too many updates.

- Generation Access logs containing information about connection continuously during the lifetime of long TCP connections from the metrics data.

- Metrics and logs supporting open-telemetry format.

- Exposing these metrics by kmesh daemon so that prometheus can scrape it.

- Unit and E2E tests.

#### Non-Goals

<!--
What is out of scope for this KEP? Listing non-goals helps to focus discussion
and make progress.
-->

- Collecting information about packet contents.

- Controlling or modifying TCP connection

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

TCP connection information will be collected using eBPF cgroup_skb hook. RingBuffer map is used for sending connection info periodically to userspace.


### Design Details

<!--
This section should contain enough information that the specifics of your
change are understandable. This may include API specs (though not always
required) or even code snippets. If there's any ambiguity about HOW your
proposal will be implemented, this is the place to discuss them.
-->

#### Collecting Metrics

Decelearing ebpf cgroup_skb hooks, which will trigger when the traffic passes through the cgroup socket.

```
SEC("cgroup_skb/ingress")
int cgroup_skb_ingress_prog(struct __sk_buff *skb)
{
    if (skb->family != AF_INET && skb->family != AF_INET6)
        return SK_PASS;

    struct bpf_sock *sk = skb->sk;
    if (!sk)
        return SK_PASS;

    if (!is_managed_by_kmesh_skb(skb))
        return SK_PASS;
    observe_on_data(sk);
    return SK_PASS;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress_prog(struct __sk_buff *skb)
{
    if (skb->family != AF_INET && skb->family != AF_INET6)
        return SK_PASS;

    struct bpf_sock *sk = skb->sk;
    if (!sk)
        return SK_PASS;

    if (!is_managed_by_kmesh_skb(skb))
        return SK_PASS;
    observe_on_data(sk);
    return SK_PASS;
}

```
Observe_on_data function checks if the time elapsed after lsat_report is greaater than 5 sec. and if it is greater, it report's the conn_info to the ring_buffer and updates the last_report_ns.

```
static inline void observe_on_data(struct bpf_sock *sk)
{
    struct bpf_tcp_sock *tcp_sock = NULL;
    struct sock_storage_data *storage = NULL;
    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        return;
    }
    __u64 now = bpf_ktime_get_ns();
    if ((storage->last_report_ns != 0) && (now - storage->last_report_ns > LONG_CONN_THRESHOLD_TIME)) {
        tcp_report(sk, tcp_sock, storage, BPF_TCP_ESTABLISHED);
    }
}
```

We will update the functions of metric.go for periodic updating the workload and service metrics, also we will create a new metric for long tcp connections.

![design](./pics/tcp_long_conn_design.png)
#### User Stories (Optional)

<!--
Detail the things that people will be able to do if this KEP is implemented.
Include as much detail as possible so that people can understand the "how" of
the system. The goal here is to make this feel real for users without getting
bogged down.
-->

##### Story 1
Workload and service prometheus metrics are updated periodically and when the connection is closed.

##### Story 2
A new prometheus metric for long tcp connection which updates periodically.

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

Updating bpf_test.go for testing the ebpf code written.
Also updating metric_test.go for testing the metrics
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

Creating a userspace proxy component instead of ebpf for collecting metrics.