/* Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <bpf_log.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include "common.h"
#include "tuple.h"
#include "tc_rev_nat.h"


#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define TCP_SPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))

static bool is_eth_ip(void *data_begin, void *data_end)
{
	struct ethhdr *eth = data_begin;
	if ((void *)(eth + 1) > data_end) //
		return false;
	// Check if Ethernet frame has IP packet
	if (eth->h_proto == bpf_htons(ETH_P_IP))
		return true;
	return false;
}


SEC("tc")
int tc_xdp_rev_nat(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct tcphdr* tcph;
	struct iphdr* iph;

	tuple_t tuple = {0};
	BPF_LOG(DEBUG, KMESH, "tc_xdp_rev_nat:enter");

	if (!is_eth_ip(data, data_end)) {
		return TC_ACT_OK;
	}

	iph = data + sizeof(struct ethhdr);
	if ((void*)(iph + 1) > data_end) {
		return TC_ACT_SHOT;
	}

	if (iph->protocol != IPPROTO_TCP) {
		return TC_ACT_OK;
	}

	tcph = (struct tcphdr *)(iph + 1);
	if ((void*)(tcph + 1) > data_end) {
		return TC_ACT_SHOT;
	}

	parse_tuple(iph, tcph, &tuple);
	// flag =1 :snat records
	tuple.flags = TUPLE_FLAGS_EGRESS;

	address_t *revSnatAddr = map_lookup_tuple_in_tc(&tuple);
	if (!revSnatAddr) {
		return TC_ACT_OK;
	}

	BPF_LOG(DEBUG, KMESH, "tc_xdp_rev_nat:origin src %u:%u, p rotocol=%u",
			tuple.src_ipv4, tuple.src_port, tuple.protocol);
	BPF_LOG(DEBUG, KMESH, "tc_xdp_rev_nat:dst %u:%u", tuple.dst_ipv4, tuple.dst_port);


	__u32 newSrcIp = revSnatAddr->ipv4;
	__u16 newSrcPort = revSnatAddr->port;
	__u32 oldSrcIp = iph->saddr;
	__u16 oldSrcPort = tcph->source;


	bpf_l4_csum_replace(skb, TCP_CSUM_OFF, oldSrcIp, newSrcIp, BPF_F_PSEUDO_HDR);
	bpf_l3_csum_replace(skb, IP_CSUM_OFF, oldSrcIp, newSrcIp, sizeof(newSrcIp));
	bpf_skb_store_bytes(skb, IP_SRC_OFF, &newSrcIp, sizeof(newSrcIp), 0);

	bpf_l4_csum_replace(skb, TCP_CSUM_OFF, oldSrcPort, newSrcPort, sizeof(newSrcPort));
	bpf_skb_store_bytes(skb, TCP_SPORT_OFF, &newSrcPort, sizeof(newSrcPort), 0);
	BPF_LOG(DEBUG, KMESH, "tc_xdp_rev_nat: new src info: %u:%u.\n", newSrcIp, newSrcPort);
	return TC_ACT_OK;
}


char _license[] SEC("license") = "GPL";