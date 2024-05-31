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

The persistence capability of the bpf map and the configuration restoration capability after the Kmesh restart need to be supported, including:

1. When the Kmesh is restarted, the bpf map and bpf prog need to be maintained without being deleted, which is the basis for maintaining the data plane governance capability.
2. After the Kmesh is restarted, the configuration restoration module is added to restore the governance information of the pods managed by the Kmesh on the node.
3. In the scenario where the Kmesh is deleted, the bpf prog and bpf map resources must be cleared in a timely manner to ensure that no resource leakage occurs.

When the Kmesh is started, the bpf prog and bpf map may already exist on the node. In this case, compatibility processing is required.

### Design Details

#### Status Quo and Strategy Analysis

The following uses the workload mode as an example to describe the operations on each BPF map during Kmesh governance:

![](pics/kmesh-workload-bpf-map.svg)

As shown in the preceding figure, these BPF maps are classified by feature as follows:

- Workload Model
  - maps: kmesh_frontend | kmesh_service | kmesh_endpoint | kmesh_backend
  - Data source/Time: When the cluster is changed, the Istiod management and control plane delivers the data.
- Kmesh management
  - maps: map_of_manager
  - Data source/Time: kmesh-plg, which is triggered when a pod is created or deleted;
- Kmesh byPass
  - maps: map_of_manager
  - Data source/Time: kmesh-daemon subscribes to pod change information and triggers the update based on the label.
- Authentication
  - maps: map_of_tuple | map_of_auth
  - Data source/Time: map_of_tuple is the table that reports the quintuple to be authenticated in the passive connect phase. The daemon authentication module updates the link information to be denied to map_of_auth in user mode. In the xdp packet receiving process, deny is performed based on map_of_auth.
- Waypoint interconnection
  - maps: map_of_dst_info
  - Data source/Time: If ndat needs to be delivered to the waypoint in the active connect phase, the original link information is added to the map_of_dst_info, and the map_of_kmesh_socket sockhash table is added to replace the send/recv hook of the socket (to facilitate the BPF hook in the triggering of the receive and transmit processes). Reads the map_of_dst_info record from the BPF prog in the send phase, constructs meta data, and adds the data to the TCP packet.

Impacts of the Kmesh restart on the preceding tables are as follows:

- During the Kmesh restart:

  | Scenario     | workload model | Kmesh management | Kmesh byPass | Auth | waypoint Interconnection                                     |
  | ------------ | -------------- | ---------------- | ------------ | ---- | ------------------------------------------------------------ |
  | Existed link | Y              | Y                | Y            | Y    | P(If the connection is complete but the send request has not been sent) |
  | New link     | N              | N                | N            | N    | N                                                            |

  Countermeasures:

  - The bpf prog and map need to be maintained during restart.

- After the Kmesh is restarted:

  | Scenario     | workload model | Kmesh management | Kmesh byPass | Auth | waypoint Interconnection |
  | ------------ | -------------- | ---------------- | ------------ | ---- | ------------------------ |
  | Existed link | Y              | Y                | Y            | Y    | Y                        |
  | New link     | Y              | N                | Y            | N    | N                        |

  Countermeasures:

  - The bpf prog and map need to be maintained during restart.
  - After the Kmesh is started, the data in the map needs to be restored and the data needs to be synchronized with the control plane.

  Note: Currently, Kmesh supports only link-level authentication.

#### Solutions



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