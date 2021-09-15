/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _SOCKMAP_H_
#define _SOCKMAP_H_

#include <stddef.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

enum bpf_loglevel {
	BPF_LOG_ERR = 0,
	BPF_LOG_WARN,
	BPF_LOG_INFO,
	BPF_LOG_DEBUG,
};

// TODO: set loglevel
#define BPF_LOGLEVEL	BPF_LOG_INFO

#define BPF_LOG(l, f, ...)								\
	do {												\
		if (BPF_LOG_ ## l <= BPF_LOGLEVEL)				\
			bpf_printk("["# l"] "f"", ##__VA_ARGS__);	\
	} while (0)

#define SKOPS_MAP_SIZE			65535
#define SKOPS_PROXY_MAP_SIZE	SKOPS_MAP_SIZE

struct sock_key {
	// network byte order
	__u32 sip4;
	__u32 dip4;
	__u32 sport;
	__u32 dport;
} __attribute__((packed));

struct bpf_map_def SEC("maps") skops_map = {
	.type			= BPF_MAP_TYPE_SOCKHASH,
	.key_size		= sizeof(struct sock_key),
	.value_size		= sizeof(int),
	.max_entries	= SKOPS_MAP_SIZE,
	.map_flags		= 0,
};

// mapping of active-passive connections
struct bpf_map_def SEC("maps") skops_proxy_map = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(struct sock_key),
	.value_size		= sizeof(struct sock_key),
	.max_entries	= SKOPS_PROXY_MAP_SIZE,
	.map_flags		= 0,
};

static inline
struct sock_key* lookup_ip4_policy(struct sock_key *key)
{
	return bpf_map_lookup_elem(&skops_proxy_map, key);
}

// for test
static inline
int policy_ip4_egress_test(__u32 port)
{
#if 1
	const __u32 cli_proxy_port = bpf_htonl(15001);
	const __u32 ser_proxy_port = bpf_htonl(15006);
	const __u32 ser_port = bpf_htonl(80);

	if (port == cli_proxy_port ||
		port == ser_proxy_port ||
		port == ser_port) {
		return 1;
	}
	return 0;
#else
	return 1;
#endif
}

#endif // _SOCKMAP_H_