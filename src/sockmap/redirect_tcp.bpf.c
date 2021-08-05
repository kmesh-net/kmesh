/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#include "sockmap.bpf.h"

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
int bpf_tcpip_bypass(struct sk_msg_md *msg)
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