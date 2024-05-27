---
title: proposal of Kmesh observability
authors:
- "@LiZhencheng9527" # Authors' GitHub accounts here.
reviewers:
- ""
- TBD
approvers:
- ""
- TBD

creation-date: 2024-05-16

---

## proposal of Kmesh observability

<!--
This is the title of your KEP. Keep it short, simple, and descriptive. A good
title can help communicate what the KEP is and should be considered as part of
any review.
-->

### Summary

<!--
This section is incredibly important for producing high-quality, user-focused
documentation such as release notes or a development roadmap.

A good summary is probably at least a paragraph in length.
-->

The importance of observability of service mesh as the basis for manageable, reliable and sustainable grid systems cannot be ignored.In istio, accesslog, metric, and tracing are provided at layers l4 and l7 to meet the user's need for observability.

In this proposal, I will analyse the observability metrics of istio. And propose that Kmesh implement observability features to support these metrics. So that users can seamlessly use Kmesh.

### Motivation

<!--
This section is for explicitly listing the motivation, goals, and non-goals of
this KEP.  Describe why the change is important and the benefits to users.
-->

#### Accesslog

In [istio ztunnel](https://github.com/istio/ztunnel?tab=readme-ov-file#logging), the Layer 4 access log contains the following metrics:

src.addr
src.workload
src.namespace
src.identity

dst.addr
dst.hbone_addr
dst.service
dst.workload
dst.namespace
dst.identity

direction

bytes_sent
bytes_recv
duration

An example of the accesslog obtained is shown below:

```console
2024-04-11T15:38:42.182974Z  INFO access: connection complete
    src.addr=10.244.0.24:46238 src.workload="shell-6d8bcd654d-t88gp" src.namespace="default" src.identity="spiffe://cluster.local/ns/default/sa/default"
    dst.addr=10.244.0.42:15008 dst.hbone_addr=10.96.108.116:80 dst.service="echo.default.svc.cluster.local"
    direction="outbound" bytes_sent=67 bytes_recv=490 duration="13ms"
```

The accesslog needs to contain the identities(address/workload/namespace/identity) of the destination and source. In addition, the required metrics are the size of the message sent(bytes_sent), the size of the message received(bytes_recv) and the duration of the link.

In order for users to be able to use Kmesh smoothly, Kmesh needs to support these accesslog.

#### Metrics

To monitor service behavior, Istio generates metrics for all service traffic in, out, and within an Istio service mesh. These metrics provide information on behaviors.

Refer to [istio ztunnel metric](https://github.com/istio/ztunnel/blob/6532c553946856b4acc326f3b9ca6cc6abc718d0/src/proxy/metrics.rs#L369) , at Layer L4, the required metric is:

```console
connection_opens: The total number of TCP connections opened
connection_close: The total number of TCP connections closed
received_bytes: The size of total bytes received during request in case of a TCP connection
sent_bytes: The size of total bytes sent during response in case of a TCP connection
on_demand_dns: The total number of requests that used on-demand DNS (unstable)
on_demand_dns_cache_misses: The total number of cache misses for requests on-demand DNS (unstable)
```

DNS-related metrics in the above metrics, as Kmesh does not yet support DNS, we will consider supporting it after the Kmesh DNS functionality is implemented.

Therefore Kmesh first needs to support `connection_opens`, `connection_close`, `received_bytes`, `sent_bytes`.

In addition to the metrics already available for istio, as Kmesh is able to get [richer metrics](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#tcp%E6%8C%87%E6%A0%87) from the kernel. This will be an advantage for Kmesh.

#### Goals

<!--
List the specific goals of the KEP. What is it trying to achieve? How will we
know that this has succeeded?
-->

It is now clear that in order to enhance the observability of Kmesh, we need to:

- Getting the required metrics from ebpf.
- Generation of accesslog from acquired data
- Support for querying metrics through Prometheus

#### Non-Goals

<!--
What is out of scope for this KEP? Listing non-goals helps to focus discussion
and make progress.
-->

- Dns related indicators.
- Metrics for the L7 layer.

### Proposal

<!--
This is where we get down to the specifics of what the proposal actually is.
This should have enough detail that reviewers can understand exactly what
you're proposing, but should not include things like API designs or
implementation. What is the desired outcome and how do we measure success?.
The "Design Details" section below is for the real
nitty-gritty.
-->

Kmesh needs to collect metrics through the kernel and pass them on to the user mode. In the user mode, accesslog is generated from metrics. And support querying metrics through kemsh localhost:15020.

### Design Details

<!--
This section should contain enough information that the specifics of your
change are understandable. This may include API specs (though not always
required) or even code snippets. If there's any ambiguity about HOW your
proposal will be implemented, this is the place to discuss them.
-->

This is because Kmesh needs to get metrics from the kernel and sent them to the user mode. We need a bpf map to record the metrics, as a vehicle for transferring.

So we need to define a bpf map that contains all the required metrics:

```console
struct conn_value {
  u64 connection_opens;
  u64 connection_closes;
  u64 received_bytes;
  u64 sent_bytes;
  u64 duration;

  __u32 destination; 
  __u32 source;
};
```

The destination and source will contain their identity information.

<!--
This part has not been modified.
-->
- **Accesslog**

In istio's sidecar mode, istiod passes the access log format to envoy via the xDS.

After the data plane parses the xDS to get the access log format, envoy collects and formats the access log according to the configuration.

So if Kmesh needs to supplement the observability capabilities of access log, it needs to implement such a pattern as well.

As shown in the follow figure, Kmesh's Ads controller passes the access log filter to the Accesslog Controller to parse out the access log format.

Then according to the configuration, monitor the workload, collect the metrics to generate access log, and store the generated access log locally or send it to istiod.

- **Metric**

In istio, telemetry filters are generated through custom metrics or built-in metrics. which are then passed to the data plane by xDS.

The data plane gets these metrics from the workload.

After that the query is performed using Prometheus. The data plane is accessed by Prometheus through a specific port to get the metric from it.

Therefore Kmesh needs to implement a two-part function to satisfy the metric in the observability feature: The first is to be able to parse the envoy filter sent by the control plane and get the required metrics from it. The second is to provide a port for Prometheus to access these metrics.

<div align="center">
<img src="pics/observability.svg" width="800" />
</div>

Observability should be achieved in both ads mode and workload mode.

In Kmesh, whether it is the ads controller or the workload controller, when parsing out the `envoy.extensions.filters` from xDS, it will hand it over to Kmesh's telemetry controller.

The xDS controller fetches the access log format and metric configurations from it. Then get the corresponding metrics from the workloads.

The telemetry controller combines the metrics into an access log based on the access log format.

For metric features, provide 15020 port for Prometheus queries.

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