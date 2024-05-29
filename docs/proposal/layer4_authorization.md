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

This article aims to explain how Kmesh achieves layer 4 authorization functionality in workload mode. For an introduction to the authentication features, please refer to:[Kmesh TCP Authorization](https://kmesh.net/en/docs/userguide/tcp_authorization/)

### Design details


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



