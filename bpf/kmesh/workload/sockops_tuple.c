/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <linux/bpf.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>
#include "bpf_log.h"
#include "workload.h"
#include "config.h"
#include "encoder.h"

#define FORMAT_IP_LENGTH (16)

enum family_type {
    IPV4,
    IPV6,
};

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
} map_of_kmesh_hashmap SEC(".maps");

static inline bool is_managed_by_kmesh(__u32 ip)
{
    __u64 key = ip;
    return bpf_map_lookup_elem(&map_of_manager, &key);
}

static inline void extract_skops_to_tuple(struct bpf_sock_ops *skops, struct bpf_sock_tuple *tuple_key)
{
    tuple_key->ipv4.saddr = skops->local_ip4;
    tuple_key->ipv4.daddr = skops->remote_ip4;
    // local_port is host byteorder
    tuple_key->ipv4.sport = bpf_htonl(skops->local_port) >> FORMAT_IP_LENGTH;
    // remote_port is network byteorder
    // openEuler 2303 convert remote port different than other linux vendor
#if !OE_23_03
    tuple_key->ipv4.dport = skops->remote_port >> FORMAT_IP_LENGTH;
#else
    tuple_key->ipv4.dport = skops->remote_port;
#endif
}

static inline void extract_skops_to_tuple_reverse(struct bpf_sock_ops *skops, struct bpf_sock_tuple *tuple_key)
{
    tuple_key->ipv4.saddr = skops->remote_ip4;
    tuple_key->ipv4.daddr = skops->local_ip4;
    // remote_port is network byteorder
    // openEuler 2303 convert remote port different than other linux vendor
#if !OE_23_03
    tuple_key->ipv4.sport = skops->remote_port >> FORMAT_IP_LENGTH;
#else
    tuple_key->ipv4.sport = skops->remote_port;
#endif
    // local_port is host byteorder
    tuple_key->ipv4.dport = bpf_htonl(skops->local_port) >> FORMAT_IP_LENGTH;
}

// clean map_of_auth
static inline void clean_auth_map(struct bpf_sock_ops *skops)
{
    struct bpf_sock_tuple tuple_key = {0};
    // auth run PASSIVE ESTABLISHED CB now. In thie state cb
    // tuple info src is server info, dst is client info
    // During the auth, src must set the client info and dst set
    // the server info when we transmitted to the kmesh auth info.
    // In this way, auth can be performed normally.
    extract_skops_to_tuple_reverse(skops, &tuple_key);
    int ret = bpf_map_delete_elem(&map_of_auth, &tuple_key);
    if (ret && ret != -ENOENT)
        BPF_LOG(ERR, SOCKOPS, "map_of_auth bpf_map_delete_elem failed, ret: %d", ret);
}

static inline void clean_dstinfo_map(struct bpf_sock_ops *skops)
{
    __u32 *key = (__u32 *)skops->sk;
    int ret = bpf_map_delete_elem(&map_of_dst_info, &key);
    if (ret && ret != -ENOENT)
        BPF_LOG(ERR, SOCKOPS, "bpf map delete destination info failed, ret: %d", ret);
}

// insert an IPv4 tuple into the ringbuf
static inline void auth_ip_tuple(struct bpf_sock_ops *skops)
{
    struct ringbuf_msg_type *msg = bpf_ringbuf_reserve(&map_of_tuple, sizeof(*msg), 0);
    if (!msg) {
        BPF_LOG(WARN, SOCKOPS, "can not alloc new ringbuf in map_of_tuple");
        return;
    }
    // auth run PASSIVE ESTABLISHED CB now. In thie state cb
    // tuple info src is server info, dst is client info
    // During the auth, src must set the client info and dst set
    // the server info when we transmitted to the kmesh auth info.
    // In this way, auth can be performed normally.
    extract_skops_to_tuple_reverse(skops, &(*msg).tuple);
    (*msg).type = (__u32)IPV4;
    bpf_ringbuf_submit(msg, 0);
}

static inline void enable_encoding_metadata(struct bpf_sock_ops *skops)
{
    int err;
    struct bpf_sock_tuple tuple_info = {0};
    extract_skops_to_tuple(skops, &tuple_info);
    err = bpf_sock_hash_update(skops, &map_of_kmesh_hashmap, &tuple_info, BPF_ANY);
    if (err)
        BPF_LOG(ERR, SOCKOPS, "enable encoding metadta failed!, err is %d", err);
}

static inline void record_ip(__u32 ip)
{
    int err;
    __u32 value = 0;
    __u64 key = ip;
    err = bpf_map_update_elem(&map_of_manager, &key, &value, BPF_NOEXIST);
    if (err)
        BPF_LOG(ERR, KMESH, "record netcookie failed!, err is %d\n", err);
}

static inline void remove_ip(__u32 ip)
{
    __u64 key = ip;
    int err = bpf_map_delete_elem(&map_of_manager, &key);
    if (err && err != -ENOENT)
        BPF_LOG(ERR, KMESH, "record netcookie failed!, err is %d\n", err);
}

static inline bool conn_from_cni_sim_add(struct bpf_sock_ops *skops)
{
    // cni sim connect 0.0.0.1:929(0x3a1)
    // 0x3a1 is the specific port handled by the cni for enable Kmesh
#if !OE_23_03
    return ((bpf_ntohl(skops->remote_ip4) == 1) && (bpf_ntohl(skops->remote_port) == 0x3a1));
#else
    return ((bpf_ntohl(skops->remote_ip4) == 1) && (bpf_ntohl(skops->remote_port) == 0x3a10000));
#endif
}

static inline bool conn_from_cni_sim_delete(struct bpf_sock_ops *skops)
{
    // cni sim connect 0.0.0.1:930(0x3a2)
    // 0x3a2 is the specific port handled by the cni for disable Kmesh
#if !OE_23_03
    return ((bpf_ntohl(skops->remote_ip4) == 1) && (bpf_ntohl(skops->remote_port) == 0x3a2));
#else
    return ((bpf_ntohl(skops->remote_ip4) == 1) && (bpf_ntohl(skops->remote_port) == 0x3a20000));
#endif
}

static inline bool ipv4_mapped_addr(__u32 ip6[4])
{
    return ip6[0] == 0 && ip6[1] == 0 && ip6[2] == 0xFFFF0000;
}

SEC("sockops")
int record_tuple(struct bpf_sock_ops *skops)
{
    if (skops->family != AF_INET && !ipv4_mapped_addr(skops->local_ip6))
        return 0;
    switch (skops->op) {
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
        if (conn_from_cni_sim_add(skops))
            record_ip(skops->local_ip4);
        if (conn_from_cni_sim_delete(skops))
            remove_ip(skops->local_ip4);
        break;
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        if (!is_managed_by_kmesh(skops->local_ip4)) // local ip4 is client ip
            break;
        if (bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG) != 0)
            BPF_LOG(ERR, SOCKOPS, "set sockops cb failed!\n");
        enable_encoding_metadata(skops);
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        if (!is_managed_by_kmesh(skops->local_ip4)) // local ip4 is server ip
            break;
        if (bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG) != 0)
            BPF_LOG(ERR, SOCKOPS, "set sockops cb failed!\n");
        auth_ip_tuple(skops);
        break;
    case BPF_SOCK_OPS_STATE_CB:
        if (skops->args[1] == BPF_TCP_CLOSE) {
            clean_auth_map(skops);
            clean_dstinfo_map(skops);
        }
        break;
    default:
        break;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
