---
title: AI Gateway Capabilities in Kmesh
authors:
- "@Yaozengzeng"
reviewers:
- "@robot"
- TBD
approvers:
- "@robot"
- TBD

creation-date: 2024-12-10

---

## AI Gateway Capabilities in Kmesh


### Summary

This proposal shows how to bring AI Gateway capabilities into Kmesh, mainly including architecture design and API design.

### Motivation

With the explosion of Generative AI, more and more Large Language Models have been deployed based on Kubernetes and the proportion of AI traffic has become more prominent. As a beneficial supplement to Kubernetes, Service Mesh can already manage traffic well, and AI traffic is no exception. But AI has its own particularity. For example, when managing AI traffic, tokens are the core unit instead of traditional requests or connections. In addition, the current cost of using LLM is still very high, so we should rate limit and also need to use semantic caching to speed up response speed, reduce costs, and minimize the resource occupation of LLM by repeated queries.

As a powerful Traffic Management Engine, Kmesh should be specially optimized for AI scenarios to make AI traffic management smoother.

Currently AI traffic management is mainly focused on the north-south direction, that is, the traffic entering from the Gateway. For general north-south traffic management functions, the open source community has already provided good support and provided multiple implementations, such as Istio Ingress Gateway, Envoy Gateway, and so on.

Kmesh can now be seamlessly integrated  with these Gateways. Obviously, the work of implementing a new Gateway from scratch is huge, and the implementation of most common functions will be a repetitive work. In addition, most Gateways are implemented based on Envoy, which is famous for its powerful extensibility. Therefor, we decided to implement Kmesh's AI capabitlity in the form of extensions plugins, which can not only reuse the community's existing capabilities, but also bring incremental benefits.

#### Goals

- Implement AI plugin that is compatible with various mainstream Gateways based on Envoy and provides capability enhancement for AI scenarios.

- Design a set of AIPs (CRDs) for AI traffic management that can work with mainstream APIs such as Gateway API while maintaining scalabitily to allow AI governance capabilities to be added incrementally.

#### Non-Goals

- Implement a new Gateway from scratch.

### Proposal

Currently AI traffic management is mainly focused on the north-south direction, that is, the traffic entering from the Gateway. For general north-south traffic management functions, the open source community has already provided good support and provided multiple implementations, such as Istio Ingress Gateway, Envoy Gateway, and so on.

Kmesh can now be seamlessly integrated  with these Gateways. Obviously, the work of implementing a new Gateway from scratch is huge, and the implementation of most common functions will be a repetitive work. In addition, most Gateways are implemented based on Envoy, which is famous for its powerful extensibility. Therefor, we decided to implement Kmesh's AI capabitlity in the form of extensions plugins, which can not only reuse the community's existing capabilities, but also bring incremental benefits.

The Kmesh's AI plugin should have the following advantages:

1. Built as an external plugin (independent of Envoy process), independently deployed and enabled on demand.
2. Gateway agnostic, able to adapt to various cloud native Gateways built on Envoy, perfectly compatible with the cloud native tech stack.
3. Built on Golang, dev-friendly, easy to extend and customize.

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