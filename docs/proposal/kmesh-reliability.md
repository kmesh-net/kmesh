---
title: Kmesh reliability
authors:
- "@kwb0523" # Authors' GitHub accounts here.
- "@nlgwcy"
reviewers:
- "@bitcoffeeiux"
- "@hzxuzhonghu"
- "@supercharge-xsy"
approvers:
- "@robot"

creation-date: 2024-06-04

---

## Kmesh reliability

### Summary

This proposal describes how to ensure that the governance capability is not affected when the Kmesh is restarted.

### Motivation

The problem is from [issue_322](https://github.com/kmesh-net/kmesh/issues/322). After the Kmesh is restarted, the pods managed by the Kmesh are no longer taken over by the Kmesh. As a result, the governance function is affected.

#### Goals

In normal and abnormal restart scenarios, the data plane governance function is not affected, including:

1. After the pod is restarted, it is automatically restored to the status before the restart.
2. During the Kmesh restart, newly established links have the governance capability.
3. After the Kmesh is restarted, the newly created link has the governance capability.
4. The governance capability of old links is not affected by restart.
5. When Kmesh is deleted, resources can be completely cleared to avoid residual resources.

#### Non-Goals

Currently, this document focuses on the Kmesh daemon restart scenario. The following scenarios are not included in the design scope:

1. Upgrade the Kmesh daemon.

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