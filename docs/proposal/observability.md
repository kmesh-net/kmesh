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

**access log:**

In istio, use [telemetry](https://istio.io/latest/docs/tasks/observability/logs/access-log/) to enable access logs and define the access log format there. The default access log format is as follows:

```console
[%START_TIME%] \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%\" %RESPONSE_CODE% %RESPONSE_FLAGS% %RESPONSE_CODE_DETAILS% %CONNECTION_TERMINATION_DETAILS%
\"%UPSTREAM_TRANSPORT_FAILURE_REASON%\" %BYTES_RECEIVED% %BYTES_SENT% %DURATION% %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% \"%REQ(X-FORWARDED-FOR)%\" \"%REQ(USER-AGENT)%\" \"%REQ(X-REQUEST-ID)%\"
\"%REQ(:AUTHORITY)%\" \"%UPSTREAM_HOST%\" %UPSTREAM_CLUSTER% %UPSTREAM_LOCAL_ADDRESS% %DOWNSTREAM_LOCAL_ADDRESS% %DOWNSTREAM_REMOTE_ADDRESS% %REQUESTED_SERVER_NAME% %ROUTE_NAME%\n
```

- %START_TIME%: Request start time, used to calculate request duration.
- %REQ(:METHOD)%：Request method, such as GET, POST etc.
- %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%：The URL path of the request, excluding the host and port information.
- %PROTOCOL%：The network protocol and version used for the request.
- %RESPONSE_CODE%：The HTTP status code returned by the server when responding to the request, such as 200, 404 etc.
- %RESPONSE_FLAGS%：Response flags indicating additional information like whether the response included a content-length or was a chunked response.
- %RESPONSE_CODE_DETAILS%: More detailed explanation of the status code, such as the specific reason for a 4xx error.
- %CONNECTION_TERMINATION_DETAILS%: How the connection was terminated, such as idle timeout or proxy timeout.
- %UPSTREAM_TRANSPORT_FAILURE_REASON%:
- %BYTES_RECEIVED%: The total number of bytes received by the proxy from the downstream client.
- %BYTES_SENT%: The total number of bytes sent by the proxy to the upstream host.
- %DURATION%: The total time taken for the request to pass through the proxy from receipt to response, in milliseconds.
- %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%: The actual time taken by the upstream service to process the request and generate the response.
- %REQ(X-FORWARDED-FOR)%: The original client IP address, with each proxied hop's IP appended.
- %REQ(USER-AGENT)%: The client's user-agent software and version identification string.
- %REQ(X-REQUEST-ID)%: A unique identifier for the request.
- %REQ(:AUTHORITY)%: The value of the HTTP request's Host header field.
- %UPSTREAM_HOST%: The real IP address or hostname of the upstream host.
- %UPSTREAM_CLUSTER%: The name of the cluster that the upstream host belongs to.
- %UPSTREAM_LOCAL_ADDRESS%: The local IP address of the proxy for its connection to the upstream node.
- %DOWNSTREAM_LOCAL_ADDRESS%: The IP and port on which the proxy listens for client connections.
- %DOWNSTREAM_REMOTE_ADDRESS%: The IP and port on which the proxy listens for client connections.
- %REQUESTED_SERVER_NAME%: The server name specified in the request.
- %ROUTE_NAME%: The name of the route that the request matched and used.

These metrics are all provided by envoy.

In order for users to be able to use Kmesh smoothly, Kmesh needs to support these metrics at a minimum.

In addition to these metrics that must be supported, we need to discuss whether Kmesh can take advantage of eEPF to access data on other user relationships. To enhance our competitiveness.

**metric:**

To monitor service behavior, Istio generates metrics for all service traffic in, out, and within an Istio service mesh. These metrics provide information on behaviors such as the overall volume of traffic, the error rates within the traffic, and the response times for requests.

The built-in support for istio's detection metrics is as follows:

```console
// refer to https://github.com/istio/api/blob/master/telemetry/v1/telemetry.pb.go

// Use of this enum indicates that the override should apply to all Istio
// default metrics.
MetricSelector_ALL_METRICS MetricSelector_IstioMetric = 0
// Counter of requests to/from an application, generated for HTTP, HTTP/2,
// and GRPC traffic.
//
// The Prometheus provider exports this metric as: `istio_requests_total`.
//
// The Stackdriver provider exports this metric as:
//
// - `istio.io/service/server/request_count` (SERVER mode)
// - `istio.io/service/client/request_count` (CLIENT mode)
MetricSelector_REQUEST_COUNT MetricSelector_IstioMetric = 1
// Histogram of request durations, generated for HTTP, HTTP/2, and GRPC
// traffic.
//
// The Prometheus provider exports this metric as:
// `istio_request_duration_milliseconds`.
//
// The Stackdriver provider exports this metric as:
//
// - `istio.io/service/server/response_latencies` (SERVER mode)
// - `istio.io/service/client/roundtrip_latencies` (CLIENT mode)
MetricSelector_REQUEST_DURATION MetricSelector_IstioMetric = 2
// Histogram of request body sizes, generated for HTTP, HTTP/2, and GRPC
// traffic.
//
// The Prometheus provider exports this metric as: `istio_request_bytes`.
//
// The Stackdriver provider exports this metric as:
//
// - `istio.io/service/server/request_bytes` (SERVER mode)
// - `istio.io/service/client/request_bytes` (CLIENT mode)
MetricSelector_REQUEST_SIZE MetricSelector_IstioMetric = 3
// Histogram of response body sizes, generated for HTTP, HTTP/2, and GRPC
// traffic.
//
// The Prometheus provider exports this metric as: `istio_response_bytes`.
//
// The Stackdriver provider exports this metric as:
//
// - `istio.io/service/server/response_bytes` (SERVER mode)
// - `istio.io/service/client/response_bytes` (CLIENT mode)
MetricSelector_RESPONSE_SIZE MetricSelector_IstioMetric = 4
// Counter of TCP connections opened over lifetime of workload.
//
// The Prometheus provider exports this metric as:
// `istio_tcp_connections_opened_total`.
//
// The Stackdriver provider exports this metric as:
//
// - `istio.io/service/server/connection_open_count` (SERVER mode)
// - `istio.io/service/client/connection_open_count` (CLIENT mode)
MetricSelector_TCP_OPENED_CONNECTIONS MetricSelector_IstioMetric = 5
// Counter of TCP connections closed over lifetime of workload.
//
// The Prometheus provider exports this metric as:
// `istio_tcp_connections_closed_total`.
//
// The Stackdriver provider exports this metric as:
//
// - `istio.io/service/server/connection_close_count` (SERVER mode)
// - `istio.io/service/client/connection_close_count` (CLIENT mode)
MetricSelector_TCP_CLOSED_CONNECTIONS MetricSelector_IstioMetric = 6
// Counter of bytes sent during a response over a TCP connection.
//
// The Prometheus provider exports this metric as:
// `istio_tcp_sent_bytes_total`.
//
// The Stackdriver provider exports this metric as:
//
// - `istio.io/service/server/sent_bytes_count` (SERVER mode)
// - `istio.io/service/client/sent_bytes_count` (CLIENT mode)
MetricSelector_TCP_SENT_BYTES MetricSelector_IstioMetric = 7
// Counter of bytes received during a request over a TCP connection.
//
// The Prometheus provider exports this metric as:
// `istio_tcp_received_bytes_total`.
//
// The Stackdriver provider exports this metric as:
//
// - `istio.io/service/server/received_bytes_count` (SERVER mode)
// - `istio.io/service/client/received_bytes_count` (CLIENT mode)
MetricSelector_TCP_RECEIVED_BYTES MetricSelector_IstioMetric = 8
// Counter incremented for every gRPC messages sent from a client.
//
// The Prometheus provider exports this metric as:
// `istio_request_messages_total`
MetricSelector_GRPC_REQUEST_MESSAGES MetricSelector_IstioMetric = 9
// Counter incremented for every gRPC messages sent from a server.
//
// The Prometheus provider exports this metric as:
// `istio_response_messages_total`
MetricSelector_GRPC_RESPONSE_MESSAGES MetricSelector_IstioMetric = 10
```

In addition to the above metrics, istio provides the [customMetric API](https://istio.io/latest/docs/tasks/observability/metrics/customize-metrics/) to customise the metrics and get the corresponding information from the [envoy](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/attributes).

Therefore Kmesh first needs to support istio's built-in metrics, which will be gradually improved in subsequent updates, taking into account the metrics supported by envoy.

#### Goals

<!--
List the specific goals of the KEP. What is it trying to achieve? How will we
know that this has succeeded?
-->

It is now clear that in order to enhance the observability of Kmesh, we need to:

- Support for metrics for accesslog.
- Support for istio's built-in metrics.
- Support promethues scratch.

#### Non-Goals

<!--
What is out of scope for this KEP? Listing non-goals helps to focus discussion
and make progress.
-->

Support for more envoy-supported metrics in subsequent update.

### Proposal

<!--
This is where we get down to the specifics of what the proposal actually is.
This should have enough detail that reviewers can understand exactly what
you're proposing, but should not include things like API designs or
implementation. What is the desired outcome and how do we measure success?.
The "Design Details" section below is for the real
nitty-gritty.
-->

Because Kmesh uses eBPF, it is designed to be implemented in the kernel state. We first need to divide the metrics to be implemented into two categories, those that can be accessed in the user state and those that can be accessed in the kernel state.  Then implement the code for the actual metric collection.

After getting the metrics, we need to:

- Implement an `access_log filter` to send the access log to the istio control plane.
- Integrates with Prometheus to support Prometheus scraping.

### Design Details

<!--
This section should contain enough information that the specifics of your
change are understandable. This may include API specs (though not always
required) or even code snippets. If there's any ambiguity about HOW your
proposal will be implemented, this is the place to discuss them.
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