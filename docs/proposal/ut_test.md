### Proposed Implementation Plan
- First: Prepare to implement unit testing in the following order: sendmsg.c → cgroup_skb.c → cgroup_sock.c.
- Test Framework: All tests will use the unitTests_BUILD_CONTEXT framework.
- Mock Functions: For each _test.c file, include the necessary mocked BPF helper functions required during testing.
- Testing Methods:
- For branches that write to BPF maps, use coll.Maps["..."] on the Go testing side to verify whether the map contents are correct.
- For branches that do not write to any map, the current approach is to use the BPF_LOG() macro to print debug information for verification.
### Detailed Implementation Points
- Mounting and Triggering Details for the Three Programs, and Current Testing Points
#### For sendmsg.c:
- Purpose: This file’s function is to prepend TLV (Type-Length-Value) metadata when sending messages.
- Attachment Point: It uses SEC("sk_msg"), so it needs to be attached at the socket message layer.
- Difference: Its mounting and triggering method differ from the other two programs.
- Current Status: We are still experimenting with how to properly attach and trigger this eBPF program.
#### Testing Points
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
### For cgroup_skb.c
-  Purpose: This file intercepts network packets and monitors or collects statistics on connections that meet certain conditions.
-  Attachment Point: Can be attached to the cgroup, following the example of the testing method used in sockops.c.
-  Triggering: The program can be triggered during connection initiation (dial) in tests.
#### Testing Points
- 1：!is_monitoring_enable() || !is_periodic_report_enable()
- When monitoring is disabled or periodic reporting is turned off, the program should skip processing.
- 2：skb->family != AF_INET && skb->family != AF_INET6
- Non-IPv4/IPv6 packets should be skipped directly.
- 3：sock_conn_from_sim(skb)
- Controls skipping of simulated connections.
- 4：is_managed_by_kmesh_skb(skb) == false
- Packets not managed by Kmesh should be skipped directly.
- 5：Packets not managed by Kmesh should be skipped directly.
- This function triggers reporting based on timing and performs operations on BPF maps.
- Corresponding maps can be checked on the Go side for testing purposes.
### For cgroup_sock.c
- Purpose:During TCP connection initiation, this function performs traffic control and records/modifies the original destination address based on Kmesh’s management logic, and executes further processing via tail call when necessary.
- Attachment Point: Can be attached to the cgroup, following the example of the testing method used in sockops.c.
#### Testing Points
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
### Both cgroup_skb.c and cgroup_sock.c are attached to the cgroup, so their mounting process is the same and the attachment and triggering have already been implemented as follows:
```
                        mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_2_cgroup(t,                                    objFilePath, "..._prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)
```
#### Triggering cgroup_skb.c
- To trigger cgroup_skb.c, the following code is needed:
```
conn, err := net.Dial("tcp", "127.0.0.1:8080")
						if err != nil {
							t.Fatalf("连接失败: %v", err)
						}
						defer conn.Close()
```
- The server-side code can be included or omitted.
- 1: Write it like this — during the TCP three-way handshake, sending packets to the server will trigger the egress program, and the client receiving packets will trigger the ingress program.
- 2：The server-side code can also be included, for example:
```
                        // ln, err := net.Listen("tcp", "127.0.0.1:8080")
						// if err != nil {
						// 	t.Fatalf("监听失败: %v", err)
						// }
						// defer ln.Close()

						// go func() {
						// 	conn, err := ln.Accept()
						// 	if err != nil {
						// 		t.Logf("Accept error: %v", err)
						// 		return
						// 	}
						// 	defer conn.Close()
						// 	io.Copy(io.Discard, conn) // 丢弃接收数据
						// }()
```
- Both ingress and egress will be triggered.
- Currently, we are still considering whether it is necessary to implement triggering only in one of these cases.
#### Triggering cgroup_sock.c
```
conn, err := net.Dial("tcp", "1.1.1.1:80") // 目标地址不重要
						if err != nil {
							t.Logf("connect failed (ok, just for trigger): %v", err)
						} else {
							conn.Close()
```
### Question
- 1
- To achieve generality for mounting to cgroup, a proName parameter can be added to this function to make it more generic.
```
func load_bpf_2_cgroup(t *testing.T, objFilename string, cgroupPath string) (*ebpf.Collection, link.Link) {
	if cgroupPath == "" {
		t.Fatal("cgroupPath is empty")
	}
	if objFilename == "" {
		t.Fatal("objFilename is empty")
	}

	// load the eBPF program
	spec := loadAndPrepSpec(t, path.Join(*testPath, objFilename))
	var (
		coll *ebpf.Collection
		err  error
	)
	
	// Load the eBPF collection into the kernel
	coll, err = ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier error: %+v", ve)
		} else {
			t.Fatal("loading collection:", err)
		}
	}
	spec.Programs["sockops_prog"].AttachType)
	lk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    constants.Cgroup2Path,
		Attach:  spec.Programs["sockops_prog"].AttachType,
		Program: coll.Programs["sockops_prog"],
	})
	t.Log(spec.Programs["sockops_prog"].AttachType)
	if err != nil {
		coll.Close()
		t.Fatalf("Failed to attach cgroup: %v", err)
	}
	return coll, lk
}
```
- Turn it into
```
func load_bpf_prog_to_cgroup(t *testing.T, objFilename string, progName string, cgroupPath string) (*ebpf.Collection, link.Link) {
	if cgroupPath == "" {
		t.Fatal("cgroupPath is empty")
	}
	if objFilename == "" {
		t.Fatal("objFilename is empty")
	}

	// load the eBPF program
	spec := loadAndPrepSpec(t, path.Join(*testPath, objFilename))
	var (
		coll *ebpf.Collection
		err  error
	)
	// Load the eBPF collection into the kernel
	coll, err = ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier error: %+v", ve)
		} else {
			t.Fatal("loading collection:", err)
		}
	}
	lk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    constants.Cgroup2Path,
		Attach:  spec.Programs[progName].AttachType,
		Program: coll.Programs[progName],
	})
	t.Log(spec.Programs[progName].AttachType)
	if err != nil {
		coll.Close()
		t.Fatalf("Failed to attach cgroup: %v", err)
	}
	return coll, lk
}
```
- 2
- Does this function need to be modified
```
func loadAndPrepSpec(t *testing.T, elfPath string) *ebpf.CollectionSpec {
	spec, err := ebpf.LoadCollectionSpec(elfPath)
	if err != nil {
		t.Fatalf("load spec %s: %v", elfPath, err)
	}
	// Unpin all maps, as we don't want to interfere with other tests
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}

	for n, p := range spec.Programs {
		switch p.Type {
		// https://docs.ebpf.io/linux/syscall/BPF_PROG_TEST_RUN/
		case ebpf.XDP, ebpf.SchedACT, ebpf.SchedCLS, ebpf.SocketFilter, ebpf.CGroupSKB, ebpf.SockOps:
			continue
		}
	
		t.Logf("Skipping program '%s' of type '%s': BPF_PROG_RUN not supported", p.Name, p.Type)
		delete(spec.Programs, n)
	}
	
	return spec
}
- The purpose of this function is to load metadata, so ebpf.SkMsg and ebpf.CGroupSockAddr need to be included to prevent deletion.
