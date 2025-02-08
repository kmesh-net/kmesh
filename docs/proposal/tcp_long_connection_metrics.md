---
title: Proposal for generating metrics for TCP long connections
authors: 
 - "yp969803"
reviewers:
- "nglwcy"
- "lizhencheng"
approvers:
- "nglwcy"
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

- Collect detailed traffic metrics (e.g. bytes send/recieved, direction, throughput, round-trip time, latency, namespace. identity) continously during the lifetime of long TCP connections.

- Reporting of metrics and access logs, at periodic time and also based on throughput (e.g. after transfer of 1mb of data).

- User can fine tune the time and throughput using yaml during kmesh deployment or can use CLI tool kmeshctl anytime.

- Access logs containing information about connection continously during the lifetime of long TCP connections.

- Metrics and logs supporting open-telemetry format.

- Exposing these metrics by kmesh daemon so that prometheus can scrape it.

- Unit and E2E tests.

#### Non-Goals

<!--
What is out of scope for this KEP? Listing non-goals helps to focus discussion
and make progress.
-->

### Proposal

<!--
This is where we get down to the specifics of what the proposal actually is.
This should have enough detail that reviewers can understand exactly what
you're proposing, but should not include things like API designs or
implementation. What is the desired outcome and how do we measure success?.
The "Design Details" section below is for the real
nitty-gritty.
-->

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