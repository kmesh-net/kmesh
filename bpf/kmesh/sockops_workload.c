/*
 * Copyright 2023 The Kmesh Authors.
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

#define AF_INET  (2)
#define AF_INET6 (10)

#define RINGBUF_SIZE (1 << 12)

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} map_of_migration SEC(".maps");

enum family_type {
    IPV4,
    IPV6,
};

struct ringbuf_msg_type {
    __u32 type; 
    struct bpf_sock_tuple tuple;
    enum family_type type;
};

SEC("sockops")
int socket_migration(struct bpf_sock_ops *skops)
{
    struct ringbuf_msg_type *msg;

    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:           
            if (skops->family == AF_INET) {
                msg = bpf_ringbuf_reserve(&map_of_mgrt, sizeof(*msg), 0);
                if (!msg) {
                    BPF_LOG(WARN, SOCKOPS, "can not alloc new ringbuf");
                    break;
                }
                (*msg).tuple.ipv4.daddr = skops->local_ip4;
                (*msg).tuple.ipv4.saddr = skops->remote_ip4;
                (*msg).tuple.ipv4.dport = bpf_htonl(skops->local_port) >> 16;
                (*msg).tuple.ipv4.sport = skops->remote_port >> 16;
                (*msg).type = (__u32)IPV4;
                bpf_ringbuf_submit(msg, 0);
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