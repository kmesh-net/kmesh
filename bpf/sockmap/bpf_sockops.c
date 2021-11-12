/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2021-09-17
 */

#include <sys/types.h>
#include <sys/socket.h>

#include "bpf_sockmap.h"

static inline
void skops_extract_ip4_key(struct bpf_sock_ops *skops, struct sock_key *key)
{
	key->sip4  = skops->local_ip4;
	key->sport = bpf_htonl(skops->local_port);

	key->dip4  = skops->remote_ip4;
	key->dport = skops->remote_port;

	return;
}

static inline
int skops_map_add(struct bpf_sock_ops *skops)
{
	struct sock_key key = {0};

	skops_extract_ip4_key(skops, &key);

	BPF_LOG(INFO, "skops_map: op %d, sport %d, dport %d\n",
		skops->op, bpf_ntohl(key.sport), bpf_ntohl(key.dport));

	return bpf_sock_hash_update(skops, &skops_map, &key, BPF_NOEXIST);
}

// # sidecar proxy policy
// --- client ---
// tcp     192.168.123.234:43148   192.168.123.238:80      ESTABLISHED + 1931/fortio
// tcp     127.0.0.1:15001         192.168.123.234:43148   ESTABLISHED -
// tcp     192.168.123.234:43150   192.168.123.238:80      ESTABLISHED +
// --- server ---
// tcp     192.168.123.238:15006   192.168.123.234:43150   ESTABLISHED -
// tcp     127.0.0.6:59609         192.168.123.238:80      ESTABLISHED +
// tcp     192.168.123.238:80      127.0.0.6:59609         ESTABLISHED - 1560/fortio
static inline
int skops_proxy_map_active_add(struct bpf_sock_ops *skops)
{
	struct sock_key key = {0};
	struct sock_key val = {0};

	key.sip4  = skops->local_ip4;
	key.sport = bpf_htonl(skops->local_port);

	skops_extract_ip4_key(skops, &val);

	return bpf_map_update_elem(&skops_proxy_map, &key, &val, BPF_NOEXIST);
}

static inline
int skops_proxy_map_passive_add(struct bpf_sock_ops *skops)
{
	int ret = 0;
	struct sock_key key = {0};
	struct sock_key *key_a;	// active 
	struct sock_key key_p;	// passive

	key.sip4  = skops->remote_ip4;
	key.sport = skops->remote_port;
	key_a = bpf_map_lookup_elem(&skops_proxy_map, &key);
	if (key_a == NULL) {
		BPF_LOG(ERR, "skops_proxy_map lookup_elem failed\n");
		return -1;
	}

	skops_extract_ip4_key(skops, &key_p);

	ret |= bpf_map_update_elem(&skops_proxy_map, key_a, &key_p, BPF_NOEXIST);
	ret |= bpf_map_update_elem(&skops_proxy_map, &key_p, key_a, BPF_NOEXIST);
	ret |= bpf_map_delete_elem(&skops_proxy_map, &key);
	return ret;
}

// TODO: remove mappings on disconnection
__attribute__((__unused__))
static inline
int skops_proxy_map_del(struct sock_key *key)
{
	return bpf_map_delete_elem(&skops_proxy_map, key);
}

SEC("sockops")
int bpf_sockops_tcp(struct bpf_sock_ops *skops)
{
	int ret;
	__u32 family, op;

	family = skops->family;
	op = skops->op;

	if (family != AF_INET) {
		return 0;
	}

	if (!policy_ip4_egress_test(bpf_htonl(skops->local_port)) &&
		!policy_ip4_egress_test(skops->remote_port)) {
		return 0;
	}

	switch (op) {
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
			ret = skops_proxy_map_active_add(skops);
			if (ret != 0) BPF_LOG(ERR, "skops_proxy_map_active_add failed\n");
			ret = skops_map_add(skops);
			if (ret != 0) BPF_LOG(ERR, "skops_map_add active failed\n");
			break;
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			ret = skops_proxy_map_passive_add(skops);
			if (ret != 0) BPF_LOG(ERR, "skops_proxy_map_passive_add failed\n");
			ret = skops_map_add(skops);
			if (ret != 0) BPF_LOG(ERR, "skops_map_add passive failed\n");
			break;
		default:
			break;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;