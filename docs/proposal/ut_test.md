---
title: Add Unit Testing Support for eBPF Programs in Kmesh
authors:
- "@wxnzb" 
reviewers:
- "@lizhencheng"

approvers:
- "@lizhencheng"

creation-date: 2025-07-15

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

- Test Framework: sendmsg.c and cgroup_sock.c will use the unitTests_BUILD_CONTEXT framework,cgroup_skb.c use the unitTests_BPF_PROG_TEST_RUN framework

- Mock Functions: For each _test.c file, include the necessary mocked BPF helper functions required during testing.

- Testing Methods:
  - For branches that write to BPF maps, use coll.Maps["..."] on the Go testing side to verify whether the map contents are correct.

### Design Details

<!--
This section should contain enough information that the specifics of your
change are understandable. This may include API specs (though not always
required) or even code snippets. If there's any ambiguity about HOW your
proposal will be implemented, this is the place to discuss them.
-->
###  sendmsg.c
### mount and set up
#### mount
- include the sockhash map in workload_sendmsg.c
```c
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __type(key, struct bpf_sock_tuple);
    __type(value, __u32);
    __uint(max_entries, MAP_SIZE_OF_MANAGER);
    __uint(map_flags, 0);
} map_of_kmesh_socket SEC(".maps");
```
- in workload_test.go
- load the eBPF program into the kernel
```go
   //load the eBPF program
 	spec := loadAndPrepSpec(t, path.Join(*testPath, objFilePath))
	var (
			coll *ebpf.Collection
			err  error
						)
	t.Log(path.Join(*testPath, objFilePath))
	// Load the eBPF collection into the kernel
	coll, err = ebpf.NewCollection(spec)
```
- Lookup the sockhash map and attach the sk_msg eBPF program to the map
```go
    sockMap := coll.Maps["km_socket"]
    t.Log(sockMap.Type())
    t.Log(ebpf.SockHash)
    prog := coll.Programs["sendmsg_prog"]
    err = link.RawAttachProgram(link.RawAttachProgramOptions{
							Attach: ebpf.AttachSkMsgVerdict,
							Target: sockMap.FD(),
							Program: prog,
						})
```
#### set up
- Establish a network connection, obtain the file descriptor (fd), insert the fd into the map, and sending messages through this fd will trigger the eBPF program
```go
    localIP := get_local_ipv4(t)
    clientPort := 12345
    serverPort := 54321
    serverSocket := localIP + ":" + strconv.Itoa(serverPort)
    listener, err := net.Listen("tcp4", serverSocket)
    if err != nil {
        t.Fatalf("Failed to start TCP server: %v", err)
    }
    defer listener.Close()

    // try to connect 
    conn, err := (&net.Dialer{
        LocalAddr: &net.TCPAddr{
            IP:   net.ParseIP(localIP),
            Port: clientPort,
        },
        Timeout: 2 * time.Second,
    }).Dial("tcp4", serverSocket)
    defer conn.Close()
    // get fd
    fd, err := getSysFd(conn)
    if err != nil {
        t.Fatal(err)
    }
  // Construct the key-value pair and then insert it.
    type bpfSockTuple4 struct {
        Saddr [4]byte
        Daddr [4]byte
        Sport uint16
        Dport uint16
        _     [24]byte // padding
    }
    var tupleKey bpfSockTuple4
    copy(tupleKey.Saddr[:], net.ParseIP(localIP).To4())
    copy(tupleKey.Daddr[:], net.ParseIP(localIP).To4())
    tupleKey.Sport = uint16(htons(uint16(clientPort)))
    tupleKey.Dport = uint16(htons(uint16(serverPort)))
    // insert fd
    fd32 := uint32(fd)
    err = sockMap.Update(&tupleKey, &fd32, ebpf.UpdateAny)
    if err != nil {
        t.Fatalf("failed to update sockhash: %v", err)
    } else {
        t.Logf("Update successful for key: %+v, fd: %d", tupleKey, fd32)
    }
```
### test

- For the sendmsg program, there are key steps:
- get_origin_dst(msg, &dst_ip, &dst_port) internally calls
- storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0); — this may need to be mocked in workload_sendmsg_test.c.
- alloc_dst_length(msg, tlv_size + TLV_END_SIZE) internally calls
- ret = bpf_msg_push_data(msg, 0, length, 0); — in tests, we currently need to observe whether this should be mocked.
- I observed that in sockops.c, auth_ip_tuple(skops); internally calls
- struct ringbuf_msg_type *msg = bpf_ringbuf_reserve(&map_of_auth_req, sizeof(*msg), 0); and it works successfully.
- SK_MSG_WRITE_BUF(msg, off, &type, TLV_TYPE_SIZE); performs the "TLV" write.
- The current plan is to write a test that directly verifies whether TLV is written into the message header.
- Validation method: Check whether TLV is correctly written into the message header.
- Validation method
```go
    buf := make([]byte, 64)
    n, _ := ln.Accept().Read(buf)
    t.Logf("Received data: %x", buf[:n])
```
### cgroup_sock.c
### mount and set up
#### mount
- in workload_test.go
```go
   // mount cgroup2
    mount_cgroup2(t, cgroupPath)
    defer syscall.Unmount(cgroupPath, 0)
    //load the eBPF program
    coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect4_prog", cgroupPath)
    defer coll.Close()
    defer lk.Close()
```
#### set up
```go
conn, err := net.Dial("tcp4", "...") 
if err != nil {
    t.Fatalf("Dial failed: %v", err)
}
defer conn.Close()
```
### test
- Currently, connect4 and connect6 each have 5 test points.
- 1
- handle_kmesh_manage_process(&kmesh_ctx) internally calls bpf_map_update_elem(&map_of_manager, &key, &value, BPF_ANY); or err = bpf_map_delete_elem(&map_of_manager, &key); for verification.
- When the destination address is CONTROL_CMD_IP: ENABLE_KMESH_PORT, it adds its netns_cookie to the map; when the destination address is CONTROL_CMD_IP: DISABLE_KMESH_PORT, it deletes its netns_cookie from the map.
- Validation method:
- Verify the addition when inserting.
```go
    kmManageMap := coll.Maps["km_manage"]
    if kmManageMap == nil {
        t.Fatal("Failed to get km_manage map from collection")
    }
    var (
        key   [16]byte
        value uint32
    )

    iter := kmManageMap.Iterate()
    count := 0

    for iter.Next(&key, &value) {
        netnsCookie := binary.LittleEndian.Uint64(key[:8])
        t.Logf("Entry %d: netns_cookie=%d, value=%d", count+1, netnsCookie, value)
        count++
    }
    if err := iter.Err(); err != nil {
        t.Fatalf("Iterate error: %v", err)
    }

    if count != 1 {
        t.Fatalf("Expected 1 entry in km_manage map, but got %d", count)
    }
```
- Validation when deleting
```go
    iter = kmManageMap.Iterate()
    count = 0
    for iter.Next(&key, &value) {
        count++
    }

    if err := iter.Err(); err != nil {
        t.Fatalf("Iterate error: %v", err)
    }
    if count != 0 {
        t.Fatalf("Expected 0 entry in km_manage map, but got %d", count)
    }
```
- Notes
- Here it may be necessary to mock storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, BPF_LOCAL_STORAGE_GET_F_CREATE); inside workload_cgroup_sock_test.c.
- 2
- The function sock_traffic_control(&kmesh_ctx) is critical and internally includes
- frontend_v = map_lookup_frontend(&frontend_k); Consider how to return frontend_v; this must return a value.
- By constructing a key-value pair so that the map contains this k-v, it can be found; construct the frontend map.
```go
    //frontend map
    type ip_addr struct {
        Raw [16]byte
    }

    type frontend_key struct {
        Addr ip_addr
    }

    type frontend_value struct {
        UpstreamID uint32
    }

    FrontendMap := coll.Maps["km_frontend"]
    var f_key frontend_key
    ip4 := net.ParseIP(localIP).To4()
    if ip4 == nil {
        t.Fatalf("invalid IPv4 address")
    }
    copy(f_key.Addr.Raw[0:4], ip4) 
    // Build the value
    f_val := frontend_value{
        UpstreamID: 1,
    }
    if err := FrontendMap.Update(&f_key, &f_val, ebpf.UpdateAny); err != nil {
        log.Fatalf("Update failed: %v", err)
    }
```
- frontend_manager(kmesh_ctx, frontend_v); internally includes
- kmesh_map_lookup_elem(&map_of_service, key)
- 2.1: can find:
- 2.1.1:
- Test point: waypoint == true in service_value
```go
type service_value struct {
    PrioEndpointCount [7]uint32
    LbPolicy          uint32
    ServicePort       [10]uint32
    TargetPort        [10]uint32
    WpAddr            ip_addr
    WaypointPort      uint32
}
wpIP := net.ParseIP("localIP").To4()
// Build the value
s_val := service_value{
    WpAddr:       ip_addr{Raw: [16]byte{}}, 
    WaypointPort: 55555,                    //Build 
}
```
- At this point, you need to monitor the forwarded address so that the forwarded connection will not be rejected

### Alternatives
```go
test:=localIp+":"+strconv.Itoa(htons(55555))
-  _, err = net.Listen("tcp4", "10.30.0.124:985")
```	
- 2.2.2:
- 2.2: If not found, perform kmesh_map_lookup_elem(&map_of_backend, key); this must return a value
- 2.2.1:
- Test point: waypoint == true in backend_value
- Construction:
```go
type backend_value struct {
    Addr         ip_addr
    ServiceCount uint32
    Service      [MAX_SERVICE_COUNT]uint32
    WpAddr       ip_addr
    WaypointPort uint32
}
    wpIP := net.ParseIP(localIP).To4()
// Build the value
b_val := backend_value{
    Addr:         ip_addr{Raw: [16]byte{}},  
    ServiceCount: 0,                           
    Service:      [MAX_SERVICE_COUNT]uint32{}, 
    WpAddr:       ip_addr{Raw: [16]byte{}},    
    WaypointPort: uint32(testPort),            
}
// map WpAddr
copy(b_val.WpAddr.Raw[0:4], wpIP)
if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
    log.Fatalf("Update failed: %v", err)
}
```
- This traffic is also forwarded, so the forwarded address must be listened to in advance.
```go
testIpPort := localIP + ":" + strconv.Itoa(htons(testPort))
_, err = net.Listen("tcp4", testIpPort)
```
- 2.2.2
- Test point: waypoint == false in backend_value
- Construction:
```go
type backend_value struct {
    Addr         ip_addr
    ServiceCount uint32
    Service      [MAX_SERVICE_COUNT]uint32
    WpAddr       ip_addr
    WaypointPort uint32
}
b_val := backend_value{
    Addr:         ip_addr{Raw: [16]byte{}},  
    ServiceCount: 0,                           
    Service:      [MAX_SERVICE_COUNT]uint32{}, 
    WpAddr:       ip_addr{Raw: [16]byte{}},    
    WaypointPort: 0,                           
}
if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
    log.Fatalf("Update failed: %v", err)
}
```
- Note: The UpstreamID in the constructed value must match the key length used later when populating km_backend or the key length used in km_service. For example:
```go
type backend_key struct {
    BackendUID uint32
}
b_key := backend_key{
    BackendUID: 1,
}
```

```go
type service_key struct {
    ServiceID uint32
}
s_key := service_key{
    ServiceID: 1,
}
```
- Validation method:
```go
expectedIP := localIP
    expectedPort := strconv.Itoa(htons(testPort))

    if host != expectedIP || port != expectedPort {
        t.Fatalf("Expected redirected to %s:%s, but got %s:%s", expectedIP, expectedPort, host, port)
    }
```
### cgroup_skb.c
- It is a type supported by bpf_prog_run and can be tested using the first framework.
- Since it uses the same __sk_buff parameters as tc triggers, it can be written by following that example.
```c
#include "ut_common.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <netinet/tcp.h>

#include "workload/cgroup_skb.c" 
struct tcp_probe_info mock_info;
bool mock_ringbuf_called = false;
static __always_inline void mock_clear()
{
    __builtin_memset(&mock_info, 0, sizeof(mock_info));
    mock_ringbuf_called = false;
}
void *bpf_ringbuf_reserve(void *ringbuf, __u64 size, __u64 flags)
{
    mock_ringbuf_called = true;
    return &mock_info; // return mock_info address
}
// Tail call map for jump
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(max_entries, 2);
    __array(values, int());
} entry_call_map SEC(".maps") = {
    .values =
        {
            [0] = &cgroup_skb_ingress_prog, // 0 号 slot into ingress
            [1] = &cgroup_skb_egress_prog,  // 1 号 slot into egress
        },
};

// 模拟 IP + TCP 头，构造简单 TCP SYN 报文
#define SRC_IP    0x0F00000A 
#define SRC_PORT  23445
#define DEST_IP   0x0F00010A
#define DEST_PORT 80

const struct ethhdr l2 = {
    .h_source = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    .h_dest = {0x12, 0x23, 0x34, 0x45, 0x56, 0x67},
    .h_proto = bpf_htons(ETH_P_IP),
};

const struct iphdr l3 = {
    .version = 4,
    .ihl = 5,
    .tot_len = 40,
    .id = 0x5438,
    .frag_off = bpf_htons(IP_DF),
    .ttl = 64,
    .protocol = IPPROTO_TCP,
    .saddr = SRC_IP,
    .daddr = DEST_IP,
};

const struct tcphdr l4 = {
    .source = bpf_htons(SRC_PORT),
    .dest = bpf_htons(DEST_PORT),
    .seq = 2922048129,
    .doff = 0,
    .syn = 1,
    .window = 64240,
};

const char payload[20] = "Cgroup SKB Test!!";

// ---------------------- PKTGEN ----------------------
/// 构造测试用数据包
PKTGEN("cgroup_skb", "cgroup_skb_ingress")
int test_ingress_pktgen(struct __sk_buff *ctx)
{
    return build_skb_packet(ctx, &l2, &l3, &l4, payload, sizeof(payload));
}

/// ---------------------- JUMP ----------------------
/// 通过 tail call 跳转执行 ingress 程序
JUMP("cgroup_skb", "cgroup_skb_ingress")
int test_ingress_jump(struct __sk_buff *ctx)
{
    // 触发 tail call
    bpf_tail_call(ctx, &entry_call_map, 0); // index 0 = ingress
    return TEST_ERROR;
}

/// ---------------------- CHECK ----------------------
/// 校验结果
CHECK("cgroup_skb", "cgroup_skb_ingress")
int test_ingress_check(struct __sk_buff *ctx)
{
    const __u32 expected_status = SK_PASS;

    test_init();
    mock_clear();
    // 校验基本信息（头部和内容）
    check_skb_packet(ctx, &expected_status, &l2, &l3, &l4, payload, sizeof(payload));
    if (!mock_ringbuf_called) {
        test_fatal("Expected bpf_ringbuf_submit to be called, but it wasn't");
    }

    test_finish();
}
```
<!--
What other approaches did you consider, and why did you rule them out? These do
not need to be as detailed as the proposal, but should include enough
information to express the idea and why it was not acceptable.
-->

<!--
Note: This is a simplified version of kubernetes enhancement proposal template.
https://github.com/kubernetes/enhancements/tree/3317d4cb548c396a430d1c1ac6625226018adf6a/keps/NNNN-kep-template
-->





