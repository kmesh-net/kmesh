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
#include "bpf_log.h"
#include "workload.h"
#include "config.h"

#define FORMAT_IP_LENGTH		(16) 

enum family_type {
	IPV4,
	IPV6,
};

struct ringbuf_msg_type {
	__u32 type;
	struct bpf_sock_tuple tuple;
};

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
	__type(key, struct kmesh_manager_key);
	__type(value, __u32);
	__uint(max_entries, MAP_SIZE_OF_MANAGER);
	__uint(map_flags, 0);
} map_of_kmesh_manager SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct bpf_sock_tuple);
	__type(value, __u32);
	__uint(max_entries, MAP_SIZE_OF_MANAGER);
	__uint(map_flags, 0);
} map_of_kmesh_hashmap SEC(".maps");

static inline int is_managed_by_kmesh(__u32 ip)
{
	struct kmesh_manager_key key = {0};
	key.ipaddress = ip;
	__u8 *value = bpf_map_lookup_elem(&map_of_kmesh_manager, &key);
	if (value)
		return 1;
	return 0;
}

static inline void extract_skops_to_tuple(struct bpf_sock_ops *skops,
	struct bpf_sock_tuple *tuple_key)
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

static inline void extract_skops_to_tuple_reverse(struct bpf_sock_ops *skops,
	struct bpf_sock_tuple *tuple_key)
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
	long ret = bpf_map_delete_elem(&map_of_auth, &tuple_key);
	if(ret && ret != -ENOENT)
		BPF_LOG(INFO, SOCKOPS, "map_of_auth bpf_map_delete_elem failed, ret: %d\n", ret);
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
		BPF_LOG(ERR, SOCKOPS, "enable encoding metadta failed!, err is %d\n", err);
}

SEC("sockops")
int record_tuple(struct bpf_sock_ops *skops)
{
	// only support IPV4
	if (skops->family != AF_INET)
		return 0;
	switch (skops->op) {
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
			if (!is_managed_by_kmesh(skops->local_ip4)) // local ip4 is client ip
				break;
			if(bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG) != 0)
				BPF_LOG(ERR, SOCKOPS, "set sockops cb failed!\n");
			enable_encoding_metadata(skops);
			break;
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			if (!is_managed_by_kmesh(skops->local_ip4)) // local ip4 is server ip
				break;
			if(bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG) != 0)
				BPF_LOG(ERR, SOCKOPS, "set sockops cb failed!\n");
			auth_ip_tuple(skops);
			break;
		case BPF_SOCK_OPS_STATE_CB:
			if(skops->args[1] == BPF_TCP_CLOSE || skops->args[1] == BPF_TCP_CLOSE_WAIT 
			|| skops->args[1] == BPF_TCP_FIN_WAIT1)
				clean_auth_map(skops);
			break;
		default:
			break;
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
