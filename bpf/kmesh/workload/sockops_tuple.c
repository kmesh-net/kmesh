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
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_log.h"
#include "workload.h"

#define AF_INET  (2)
#define AF_INET6 (10)

enum family_type {
    IPV4,
    IPV6,
};

struct ringbuf_msg_type {
    __u32 type; 
    struct bpf_sock_tuple tuple;
};

// return 1 if pod with skops.daddr is managed by Kmesh, else return 0
static inline int dst_is_managed(struct bpf_sock_ops *skops)
{
    return 0;
}

static inline void build_auth_key(struct bpf_sock_ops *skops, struct bpf_sock_tuple* key)
{
    if(key) {
        key->ipv4.saddr = skops->remote_ip4;
        key->ipv4.sport = skops->remote_port >> 16;
        key->ipv4.daddr = skops->local_ip4;
        key->ipv4.dport = bpf_htonl(skops->local_port) >> 16;
    }
}

// clean map_of_auth
static inline void clean_auth_map(struct bpf_sock_ops *skops)
{
    struct bpf_sock_tuple tuple_key = {0};
    build_auth_key(skops, &tuple_key);
    long ret = bpf_map_delete_elem(&map_of_auth, &tuple_key);
    if(ret && ret != -ENOENT) {
        BPF_LOG(INFO, SOCKOPS, "map_of_auth bpf_map_delete_elem failed, ret: %d\n", ret);
    }
}

// insert an IPv4 tuple into the ringbuf, return 0 if succeed, 1 if failed
static inline int insert_ipv4_tuple(struct bpf_sock_ops *skops)
{
    if (skops->family == AF_INET) {
        struct ringbuf_msg_type *msg = bpf_ringbuf_reserve(&map_of_tuple, sizeof(*msg), 0);
        if (!msg) {
            BPF_LOG(WARN, SOCKOPS, "can not alloc new ringbuf in map_of_tuple");
          return 1;
        }
        (*msg).tuple.ipv4.daddr = skops->local_ip4;
        (*msg).tuple.ipv4.saddr = skops->remote_ip4;
        // local_port is host byteorder
        (*msg).tuple.ipv4.dport = bpf_htonl(skops->local_port) >> 16;
        // remote_port is network byteorder
        (*msg).tuple.ipv4.sport = skops->remote_port >> 16;
        (*msg).type = (__u32)IPV4;
        bpf_ringbuf_submit(msg, 0);
    }
    return 0;
}

SEC("sockops")
int record_tuple(struct bpf_sock_ops *skops)
{
    if(!dst_is_managed(skops)) {
        return 0;
    }

    switch (skops->op) {
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            if(bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG) != 0){
                BPF_LOG(ERR, SOCKOPS, "set sockops cb failed!\n");
            }
            break;
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            if(bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG) != 0){
                BPF_LOG(ERR, SOCKOPS, "set sockops cb failed!\n");
            }           
            if(insert_ipv4_tuple(skops)) {
                break;
            }
        case BPF_SOCK_OPS_STATE_CB:
            if(skops->args[1] == BPF_TCP_CLOSE || skops->args[1] == BPF_TCP_CLOSE_WAIT 
            || skops->args[1] == BPF_TCP_FIN_WAIT1) {
                clean_auth_map(skops);
            }
            // not support IPV6
            break;
        default:
            break;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;