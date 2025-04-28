// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>
#include "bpf_log.h"
#include "workload.h"
#include "bpf_common.h"
#include "probe.h"
#include "config.h"

#define FORMAT_IP_LENGTH (16)

struct ringbuf_msg_type {
    __u32 type;
    struct bpf_sock_tuple tuple;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __type(key, struct bpf_sock_tuple);
    __type(value, __u32);
    __uint(max_entries, MAP_SIZE_OF_MANAGER);
    __uint(map_flags, 0);
} map_of_kmesh_socket SEC(".maps");

volatile __u32 node_ip[4];
volatile __u32 pod_gateway[4];

static inline bool skip_specific_probe(struct bpf_sock_ops *skops)
{
    if (skops->family == AF_INET) {
        if (node_ip[3] == skops->remote_ip4) {
            return true;
        }
        if (pod_gateway[3] == skops->remote_ip4) {
            return true;
        }
    }

    if (skops->family == AF_INET6) {
        if (node_ip[0] == skops->remote_ip6[0] && node_ip[1] == skops->remote_ip6[1]
            && node_ip[2] == skops->remote_ip6[2] && node_ip[3] == skops->remote_ip6[3]) {
            return true;
        }
        if (pod_gateway[0] == skops->remote_ip6[0] && pod_gateway[1] == skops->remote_ip6[1]
            && pod_gateway[2] == skops->remote_ip6[2] && pod_gateway[3] == skops->remote_ip6[3]) {
            return true;
        }
    }

    return false;
}

static inline void extract_skops_to_tuple(struct bpf_sock_ops *skops, struct bpf_sock_tuple *tuple_key)
{
    if (skops->family == AF_INET) {
        tuple_key->ipv4.saddr = skops->local_ip4;
        tuple_key->ipv4.daddr = skops->remote_ip4;
        // local_port is host byteorder, need to htons
        tuple_key->ipv4.sport = bpf_htons(GET_SKOPS_LOCAL_PORT(skops));
        // remote_port is network byteorder
        tuple_key->ipv4.dport = GET_SKOPS_REMOTE_PORT(skops);
    }
    if (skops->family == AF_INET6) {
        bpf_memcpy(tuple_key->ipv6.saddr, skops->local_ip6, IPV6_ADDR_LEN);
        bpf_memcpy(tuple_key->ipv6.daddr, skops->remote_ip6, IPV6_ADDR_LEN);
        // local_port is host byteorder, need to htons
        tuple_key->ipv6.sport = bpf_htons(GET_SKOPS_LOCAL_PORT(skops));
        // remote_port is network byteorder
        tuple_key->ipv6.dport = GET_SKOPS_REMOTE_PORT(skops);
    }
}

static inline void extract_skops_to_tuple_reverse(struct bpf_sock_ops *skops, struct bpf_sock_tuple *tuple_key)
{
    if (skops->family == AF_INET) {
        tuple_key->ipv4.saddr = skops->remote_ip4;
        tuple_key->ipv4.daddr = skops->local_ip4;
        // remote_port is network byteorder
        tuple_key->ipv4.sport = GET_SKOPS_REMOTE_PORT(skops);
        // local_port is host byteorder
        tuple_key->ipv4.dport = bpf_htons(GET_SKOPS_LOCAL_PORT(skops));
    }
    if (skops->family == AF_INET6) {
        bpf_memcpy(tuple_key->ipv6.saddr, skops->remote_ip6, IPV6_ADDR_LEN);
        bpf_memcpy(tuple_key->ipv6.daddr, skops->local_ip6, IPV6_ADDR_LEN);
        // remote_port is network byteorder
        tuple_key->ipv6.sport = GET_SKOPS_REMOTE_PORT(skops);
        // local_port is host byteorder
        tuple_key->ipv6.dport = bpf_htons(GET_SKOPS_LOCAL_PORT(skops));
    }

    if (is_ipv4_mapped_addr(tuple_key->ipv6.daddr) || is_ipv4_mapped_addr(tuple_key->ipv6.saddr)) {
        tuple_key->ipv4.saddr = tuple_key->ipv6.saddr[3];
        tuple_key->ipv4.daddr = tuple_key->ipv6.daddr[3];
        tuple_key->ipv4.sport = tuple_key->ipv6.sport;
        tuple_key->ipv4.dport = tuple_key->ipv6.dport;
    }
}

// clean map_of_auth_result
static inline void clean_auth_map(struct bpf_sock_ops *skops)
{
    struct bpf_sock_tuple tuple_key = {0};
    // auth run PASSIVE ESTABLISHED CB now. In this state cb
    // tuple info src is server info, dst is client info
    // During the auth, src must set the client info and dst set
    // the server info when we transmitted to the kmesh auth info.
    // In this way, auth can be performed normally.
    extract_skops_to_tuple_reverse(skops, &tuple_key);
    int ret = bpf_map_delete_elem(&map_of_auth_result, &tuple_key);
    if (ret && ret != -ENOENT)
        BPF_LOG(ERR, SOCKOPS, "map_of_auth_result bpf_map_delete_elem failed, ret: %d", ret);
}

// insert an IP tuple into the ringbuf
static inline void auth_ip_tuple(struct bpf_sock_ops *skops)
{
    struct ringbuf_msg_type *msg = bpf_ringbuf_reserve(&map_of_auth_req, sizeof(*msg), 0);
    if (!msg) {
        BPF_LOG(WARN, SOCKOPS, "can not alloc new mem in map_of_auth_req");
        return;
    }
    // auth run PASSIVE ESTABLISHED CB now. In this state cb
    // tuple info src is server info, dst is client info
    // During the auth, src must set the client info and dst set
    // the server info when we transmitted to the kmesh auth info.
    // In this way, auth can be performed normally.
    extract_skops_to_tuple_reverse(skops, &(*msg).tuple);
    (*msg).type = (skops->family == AF_INET) ? IPV4 : IPV6;
    if (is_ipv4_mapped_addr(skops->local_ip6)) {
        (*msg).type = IPV4;
    }
    bpf_ringbuf_submit(msg, 0);
}

// update sockmap to trigger sk_msg prog to encode metadata before sending to waypoint
static inline void enable_encoding_metadata(struct bpf_sock_ops *skops)
{
    int err;
    struct bpf_sock_tuple tuple_info = {0};
    extract_skops_to_tuple(skops, &tuple_info);
    err = bpf_sock_hash_update(skops, &map_of_kmesh_socket, &tuple_info, BPF_ANY);
    if (err)
        BPF_LOG(ERR, SOCKOPS, "enable encoding metadata failed!, err is %d", err);
}

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *skops)
{
    if (skops->family != AF_INET && skops->family != AF_INET6)
        return 0;

    switch (skops->op) {
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
        skops_handle_kmesh_managed_process(skops);
        break;
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        if (!is_managed_by_kmesh(skops))
            break;
        observe_on_connect_established(skops->sk, OUTBOUND);
        if (bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG) != 0)
            BPF_LOG(ERR, SOCKOPS, "set sockops cb failed!\n");
        struct bpf_sock *sk = (struct bpf_sock *)skops->sk;
        if (!sk) {
            break;
        }
        struct sock_storage_data *storage = NULL;
        storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
        if (!storage) {
            break;
        }

        if (storage->via_waypoint) {
            enable_encoding_metadata(skops);
        }
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        if (!is_managed_by_kmesh(skops) || skip_specific_probe(skops))
            break;
        observe_on_connect_established(skops->sk, INBOUND);
        if (bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG) != 0)
            BPF_LOG(ERR, SOCKOPS, "set sockops cb failed!\n");
        auth_ip_tuple(skops);
        break;
    case BPF_SOCK_OPS_STATE_CB:
        if (skops->args[1] == BPF_TCP_CLOSE) {
            observe_on_close(skops->sk);
            clean_auth_map(skops);
        }
        break;
    default:
        break;
    }
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;