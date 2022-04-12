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
#include "xdp.h"

static inline int l4_manager(struct xdp_md* xdp_ctx, address_t* dst_address, listener_t *listener)
{
	map_key_t cluster_map_key;
	ctx_key_t ctx_key;
	if (listener->state & LISTENER_STATE_PASSIVE)
		return 0;

	cluster_map_key = listener->map_key;

	ctx_key.address = *dst_address;
	ctx_key.tail_call_index = KMESH_TAIL_CALL_CLUSTER;
	if (kmesh_tail_update_ctx(&ctx_key, &cluster_map_key) != 0)
		return -ENOSPC;

	bpf_tail_call(xdp_ctx, &map_of_tail_call_prog, KMESH_TAIL_CALL_CLUSTER);
	kmesh_tail_delete_ctx(&ctx_key);

	return  0;
}
static inline int redirect_to_endpoints(struct xdp_md* xdp_ctx, address_t* src_address, address_t* dst_address)
{
	int ret;
	listener_t *listener = NULL;
	address_t *target = NULL;

	DECLARE_TUPLE(src_address, dst_address, tuple);
	tuple.flags = TUPLE_FLAGS_INGRESS;
	target = map_lookup_tuple_ct(&tuple);
	if (target) {
		BPF_LOG(DEBUG, KMESH, "find exist record in tuple, do xdp_nat\n");
		xdp_dnat(xdp_ctx, src_address, dst_address, target, false);
		return XDP_PASS;
	}

	listener = map_lookup_listener(dst_address);
	// no listener :not visit to k8s object
	if (listener == NULL) {
		BPF_LOG(DEBUG, KMESH, "find no listener, dst: address %u, port %u\n",
				dst_address->ipv4, dst_address->port);
		return XDP_PASS;
	}

	BPF_LOG(DEBUG, KMESH, "find listener, dst: address %u, port %u\n",
			dst_address->ipv4, dst_address->port);
	BPF_LOG(DEBUG, KMESH, "listener: address %u, port %u\n",
			listener->address.ipv4, listener->address.port);

	ret = l4_manager(xdp_ctx, dst_address, listener);
	if (ret != 0) {
		BPF_LOG(ERR, KMESH, "failed to manger packet, dst: address %u, listener: address %u\n",
				dst_address->ipv4, listener->address.ipv4);
		return XDP_ABORTED;
	}
	return XDP_PASS;
}

static inline int process_packet(struct xdp_md* xdp_ctx)
{
	address_t dst_addr = {0};
	address_t src_addr = {0};

	int ret = parse_xdp_address(xdp_ctx, false, &src_addr, &dst_addr);
	if (ret != XDP_FURTHER_PROCESSING) {
		BPF_LOG(DEBUG, KMESH, "parse_xdp_address return %u\n", ret);
		return ret;
	}
	return redirect_to_endpoints(xdp_ctx,  &src_addr, &dst_addr);
}

/* Balance xdp bpf prog */
SEC("xdp_balance")
int xdp_load_balance(struct xdp_md *ctx)
{
	void* data = (void*)(unsigned long)ctx->data;
	void* data_end = (void*)(unsigned long)ctx->data_end;
	struct ethhdr* eth = data;

	if ((void*)(eth + 1) > data_end) {
		// bogus packet, len less than minimum ethernet frame size
		BPF_LOG(DEBUG, KMESH, "xdp_load_balance invalid data\n");
		return XDP_DROP;
	}

	// only support ipv4 now
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		return process_packet(ctx);
	} else {
		BPF_LOG(DEBUG, KMESH, "only support ETH_P_IP, now is %u\n", eth->h_proto);
		return XDP_PASS;
	}
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
