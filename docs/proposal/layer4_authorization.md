---
title: support layer 4 authorization in kmesh workload mod 
authors:
- "@supercharge-xsy"
reviewers:
- "@hzxuzhonghu"
- "@nlwcy"
approvers:
- "@robot"
- TBD

creation-date: 2024-05-28
---
## Support L4 authorization in workload mode

### Summary

This article aims to explain how Kmesh achieves layer 4 authorization functionality in workload mode. For an introduction to the authentication features, please refer to:[Kmesh TCP Authorization](https://kmesh.net/en/docs/userguide/tcp_authorization/). Currently, Kmesh supports two authentication architectures. Packets are first processed through XDP authentication, and if that type is not supported, quintuple information is passed through a ring buffer for user-space authentication. The ultimate goal is to fully handle authentication in XDP.

### Userspace authentication

#### Design detail

![l4_authz](pics/kmesh_l4_authorization.svg#pic_center)

#### Map definition

```.c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bpf_sock_tuple);
    __type(value, __u32); // init, deny, allow
    __uint(max_entries, MAP_SIZE_OF_AUTH);
} map_of_auth SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} map_of_tuple SEC(".maps");


```

#### Processing logic

1. **sock-bpf:** During the connection establishment process, on the server side, sock bpf logic is triggered at the established phase. If the server is managed by Kmesh:
   - 1.1: Tuple information is recorded into `tuple_map`, which is a ringbuffer type map, readily accessible for real-time reading by the Kmesh-daemon.
   - 1.2: An `auth_map` entry is initialized with its value set to `init`, indicating that migration authentication is underway.
2. **kmesh-daemon:** The kmesh-daemon is responsible for subscribing to authorization rules and matching these rules for authorization checks.
   - 2.1: It reads the tuple records from `tuple_map`. Once read, the record in the ringbuffer map is automatically cleared by the system.
   - 2.2: Based on the read tuple information, it matches the authorization rules. If it's an `allow`, the `init` record in the table is cleared; if it's a `deny`, the value is refreshed from `init` to `deny`.
3. **xdp-bpf**: When the client sends a message and the server receives it, passing through the xdp bpf program:
   - 3.1: It matches data in `auth_map` using the five-tuple information. If a match is found with the value set to `init`, indicating the migration authentication is not yet complete, the message is temporarily discarded.
   - 3.2: If the matched record shows `value=deny`, it alters the message flag, sends an RST message to the server, clears the corresponding `auth_map` record. If no record is matched, implying authorization is allowed, the message is passed through.
4. **client retry**: The client attempts to send another message, but because the server has closed the connection, the client receives a "reset by peer" signal and subsequently closes its own channel.

### Xdp authentication

#### Design detail

![l4_authz_xdp](pics/kmesh_l4_authorization_xdp.svg#pic_center)

#### Map definition

map_of_wl_policy: records the policies that are configured for the workload.

map_of_authz_policy: records the authz rules of policies.

kmesh_tc_args: store the params that xdp_auth needs to use during the tail call

```.c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(wl_policies_v));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_AUTH_POLICY);
} map_of_wl_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(Istio__Security__Authorization));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_AUTH_POLICY);
} map_of_authz_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct bpf_sock_tuple));
    __uint(value_size, sizeof(struct match_context));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_AUTH_TAILCALL);
} kmesh_tc_args SEC(".maps");
```

#### Istio policy module

![istio_policy_module](pics/istio_policy_module.png#pic_center)

The structural diagram of istio storage policy is shown above. The Istio authorization model enforces policies through the `Istio__Security__Authorization` resource. Within this model, a workload can be associated with multiple policy rules, where policies are OR-ed. Each policy comprises various rules, which are similarly assessed OR-ed. A rule is further decomposed into multiple clauses, which are evaluated using an AND logic, meaning that all clauses must be satisfied for the rule to be considered valid. Finally, each clause contains multiple matches, assessed OR-ed, where the satisfaction of any match is sufficient for the clause to be deemed fulfilled. The policy layer also includes the authentication action, which ultimately determines the authentication strategy

#### Processing logic

![l4_authz_xdp](pics/kmesh_xdp_authz.jpg#pic_center)

In the implementation of XDP authentication, due to the limitation of eBPF verifier on the number of bytes, we need to use eBPF's tailcall mechanism to implement the entire process of XDP authentication. The whole process is shown in the figure above:
First, the program entry is xdp_authz. In this eBPF program, the starting address of the authentication rule in memory will be written to kmesh_tc_args eBPF map, and then tail call will be made to the policies_check eBPF program. This program will write the rule and necessary information to kmesh_tc_args eBPF map, and then tail call will be made to the policy_check eBPF program to check the specific clause rules, which involves matching logic such as port_check and ip_check.

![l4_authz_xdp_process](pics/kmesh_l4_authorization_match_chain.svg#pic_center)

1. Message Parsing: When a packet enters the XDP processing logic on the server side, the tuple information of the packet is parsed. The corresponding workload instance is then located based on the destination IP, and the authentication rules configured on that workload are retrieved.
2. Rule Matching: As shown in the figure, XDP implements a matching chain logic. First, it determines whether to allow or deny the packet based on the port info, if the result is deny, the packet is intercepted, and the process ends. If the result is allow, the next matching logic (e.g., IP matching) is called using function call. This process is repeated until the last link in the chain. If the final result is allow, XDP\_PASS is returned, and the packet is forwarded through the kernel network stack to the server.
