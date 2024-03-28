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
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include "config.h"
#include "bpf_log.h"
#include "ctx/tuple.h"

/*
 * containerID: hash for container id
 * ipaddress: pod ip managed by Kmesh
 * Either containerID or ipaddress must be set to 0.
 * index: if ipaddress is set, index must be 0
 *        if containerID is set, index == 0, map value is number of ips in containerID
 *        if containerID is set, index > 0, map value is an ip for the containerID
 * eg:
 * there have a containerID and its hash is 64334212, it have 3 ip address in pod
 * there have 7 record in thie map.
 *      |containerID        |ip     |index      |||value        |
 * 1.   |64334214           |0      |0          |||3            |
 * 2.   |64334214           |0      |1          |||ip1          |
 * 3.   |64334214           |0      |2          |||ip2          |
 * 4.   |64334214           |0      |3          |||ip3          |
 * 5.   |0                  |ip1    |0          |||0            |
 * 6.   |0                  |ip2    |0          |||0            |
 * 7.   |0                  |ip3    |0          |||0            |
 *
 * Why design it that way?
 * We need a way to mark in the cni whether the current ip is managed by Kmesh.
 * The cni inserts the ip address into the map when the pod is created and removes the ip
 * address from the map when the pod is destroyed.
 * However, according to the cni guide, when deleting the data, only the CONTAINER and IFNAME
 * (https://github.com/containernetworking/cni.dev/blob/main/content/docs/spec.md#del-remove-container-from-network-or-un-apply-modifications)
 * must be transferred. The IP address is not transferred in the cni. Therefore, the
 * containerID and IP address must be bound and stored in the map for subsequent deletion.
 */
struct kmesh_manager_key {
    __u64 containerID;
    __u32 ipaddress;
    __u32 index;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct kmesh_manager_key));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAP_SIZE_OF_MAX);
    __uint(map_flags, 0);
} map_of_kmesh_manager SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(key_size, sizeof(struct tuple));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAP_SIZE_OF_MAX);
    __uint(map_flags, 0);
} map_of_kmesh_hashmap SEC(".maps");

static inline int check_sock_enable_kmesh(__u32 ip)
{
    struct kmesh_manager_key key = {0};
    key.ipaddress = ip;
    __u8 *value = bpf_map_lookup_elem(&map_of_kmesh_manager, &key);
    if (value)
        return 1;
    return 0;
}

static inline void extract_key4_from_ops(struct bpf_sock_ops *ops, struct tuple *key)
{
    key->src.ip = ops->local_ip4;
    key->src.port = bpf_htonl(ops->local_port) >> FORMAT_IP_LENGTH;
    key->dst.ip = ops->remote_ip4;
    key->dst.port = force_read(ops->remote_port) >> FORMAT_IP_LENGTH;
}

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *skops)
{
    struct tuple tuple_info;
    extract_key4_from_ops(skops, &tuple_info);

    switch (skops->op) {
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            if (check_sock_enable_kmesh(tuple_info.src.ip))
                bpf_sock_hash_update(skops, &map_of_kmesh_hashmap, &tuple_info, BPF_ANY);
            break;
    }
    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;