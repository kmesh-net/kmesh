---
title: Add Unit Testing Support for eBPF Programs in Kmesh
authors:
- "@wxnzb" 
reviewers:
- "@lizhencheng"

approvers:
- "@lizhencheng"

creation-date: 2025-01-15

---


### Summary

<!--
This section is incredibly important for producing high-quality, user-focused
documentation such as release notes or a development roadmap.

A good summary is probably at least a paragraph in length.
-->

### Motivation

<!--
This section is for explicitly listing the motivation, goals, and non-goals of
this KEP.  Describe why the change is important and the benefits to users.
-->

When developing eBPF programs in Kmesh, verifying their functionality requires compiling and performing black-box testing. Following Cilium's approach, we introduced a dedicated testing framework for eBPF programs. The framework is now fully set up, and we need contributors to help complete the test cases for each eBPF program.

#### Goals

<!--
List the specific goals of the KEP. What is it trying to achieve? How will we
know that this has succeeded?
-->

- Successfully running unit test code for Kmesh's eBPF sendMsg program.

- Successfully running unit test code for Kmesh's eBPF cgroup program.

- Documentation written in English for the tests of both sendMsg and cgroup programs.
 
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

- Prepare to implement unit testing in the following order: sendmsg.c → cgroup_skb.c → cgroup_sock.c.

- Test Framework: All tests will use the unitTests_BUILD_CONTEXT framework.

- Mock Functions: For each _test.c file, include the necessary mocked BPF helper functions required during testing.

- Testing Methods:
- For branches that write to BPF maps, use coll.Maps["..."] on the Go testing side to verify whether the map contents are correct.
- For branches that do not write to any map, the current approach is to use the BPF_LOG() macro to print debug information for verification.


### Design Details

<!--
This section should contain enough information that the specifics of your
change are understandable. This may include API specs (though not always
required) or even code snippets. If there's any ambiguity about HOW your
proposal will be implemented, this is the place to discuss them.
-->

- Detailed Implementation Points
- Mounting and Triggering Details for the Three Programs, and Current Testing Points


- For sendmsg.c
- Purpose: This file’s function is to prepend TLV (Type-Length-Value) metadata when sending messages.
- Attachment Point: It uses SEC("sk_msg"), so it needs to be attached at the socket message layer.
- Difference: Its mounting and triggering method differ from the other two programs.
- Current Status: We are still experimenting with how to properly attach and trigger this eBPF program.

- Testing Points
- 1：msg->family != AF_INET && msg->family != AF_INET6
- Messages that are neither IPv4 nor IPv6 should be skipped directly.
- 2：Inside the function get_origin_dst(struct sk_msg_md *msg, struct ip_addr *dst_ip, __u16 *dst_port)
- The condition if (!storage || !storage->via_waypoint || storage->has_encoded) means:
- If storage->via_waypoint is false, it indicates the message does not pass through a Waypoint, so no TLV needs to be constructed.
- If storage->has_encoded is true, it means the TLV has already been inserted before and should not be inserted again.
- 3：alloc_dst_length(msg, tlv_size + TLV_END_SIZE)
- Tests related to buffer memory extension.
- 4：SK_MSG_WRITE_BUF(msg, off, &type, TLV_TYPE_SIZE);
- SK_MSG_WRITE_BUF(msg, off, &addr_size, TLV_LENGTH_SIZE);
- encode_metadata_end(msg, off);
- Verify that the TLV data is correctly written into the buffer.



- For cgroup_skb.c
-  Purpose: This file intercepts network packets and monitors or collects statistics on connections that meet certain conditions.
-  Attachment Point: Can be attached to the cgroup, following the example of the testing method used in sockops.c.
-  Triggering: The program can be triggered during connection initiation (dial) in tests.
  
- Testing Points
- 1：!is_monitoring_enable() || !is_periodic_report_enable()
- When monitoring is disabled or periodic reporting is turned off, the program should skip processing.
- 2：skb->family != AF_INET && skb->family != AF_INET6
- Non-IPv4/IPv6 packets should be skipped directly.
- 3：sock_conn_from_sim(skb)
- Controls skipping of simulated connections.
- 4：is_managed_by_kmesh_skb(skb) == false
- Packets not managed by Kmesh should be skipped directly.
- 5：observe_on_data(sk);
- This function triggers reporting based on timing and performs operations on BPF maps.
- Corresponding maps can be checked on the Go side for testing purposes.



- For cgroup_sock.c
- Purpose:During TCP connection initiation, this function performs traffic control and records/modifies the original destination address based on Kmesh’s management logic, and executes further processing via tail call when necessary.
- Attachment Point: Can be attached to the cgroup, following the example of the testing method used in sockops.c.

- Testing Points
- 1：handle_kmesh_manage_process(&kmesh_ctx) || !is_kmesh_enabled(ctx)
- If the connection originates from the control plane, or if the current network namespace is not managed by Kmesh, skip processing.
- 2：ctx->protocol != IPPROTO_TCP
- Skip non-TCP protocols.
- 3：frontend_v = map_lookup_frontend(&frontend_k);
- If the lookup fails (no frontend found), skip processing.
- 4：service_v = map_lookup_service(&service_k);
- Branches depending on whether the service is found.
- 5：set_original_dst_info()
- Verify that the original destination address is correctly written into the bpf_sk_storage structure.


- Both cgroup_skb.c and cgroup_sock.c are attached to the cgroup, so their mounting process is the same and the attachment and triggering have already been implemented as follows 

```
                        mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_2_cgroup(t, objFilePath, "..._prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)
```



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





