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

#include "bpf_sockmap.h"

static inline
void skmsg_extract_ip4_key(struct sk_msg_md *msg, struct sock_key *key)
{
	// network byte order
	key->sip4  = msg->local_ip4;
	key->sport = bpf_htonl(msg->local_port);

	key->dip4  = msg->remote_ip4;
	key->dport = msg->remote_port;

	return;
}

SEC("sk_msg")
int bpf_redirect_tcp(struct sk_msg_md *msg)
{
	int ret = SK_DROP;
	struct sock_key key;
	struct sock_key *pair;

	if (!policy_ip4_egress_test(bpf_htonl(msg->local_port)) &&
		!policy_ip4_egress_test(msg->remote_port)) {
		return SK_PASS;
	}

	skmsg_extract_ip4_key(msg, &key);
	pair = lookup_ip4_policy(&key);
	if (pair != NULL) {
		ret = bpf_msg_redirect_hash(msg, &skops_map, pair, BPF_F_INGRESS);
	}

	BPF_LOG(DEBUG, "sk_msg: sport %d, dport %d, ret %d\n",
			bpf_ntohl(key.sport), bpf_ntohl(key.dport), ret);

	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;