/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *	 http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: nlgwcy
 * Create: 2022-02-14
 */
#ifndef __KMESH_LISTENER_H__
#define __KMESH_LISTENER_H__

#include "kmesh_common.h"
#include "tail_call.h"
#include "listener/listener.pb-c.h"

bpf_map_t SEC("maps") map_of_listener = {
	.type			   = BPF_MAP_TYPE_HASH,
	.key_size		   = sizeof(address_t),
	.value_size		 = sizeof(Listener__Listener),
	.max_entries		= MAP_SIZE_OF_LISTENER,
	.map_flags		  = 0,
};

static inline Listener__Listener *map_lookup_listener(const address_t *addr)
{
	return kmesh_map_lookup_elem(&map_of_listener, addr);
}

static inline bool listener_filter_chain_match_check(const Listener__FilterChain *filter_chain,
						  const address_t *addr,
						  const ctx_buff_t *ctx)
{
	char *transport_protocol;
	const char buf[] = "raw_buffer";

	Listener__FilterChainMatch *filter_chain_match =
		kmesh_get_ptr_val(filter_chain->filter_chain_match);
	if (!filter_chain_match)
		return false;

	if (filter_chain_match->destination_port != 0 &&
		filter_chain_match->destination_port != addr->port)
		return false;

	transport_protocol = kmesh_get_ptr_val(filter_chain_match->transport_protocol);
	if (!transport_protocol) {
		BPF_LOG(ERR, LISTENER, "transport_protocol is NULL\n");
		return false;
	} else if (bpf_strcmp(buf, transport_protocol) != 0) {
		return false;
	}

	// TODO: application_protocols

	BPF_LOG(DEBUG, LISTENER, "match filter_chain, name=\"%s\"\n",
		(char *)kmesh_get_ptr_val(filter_chain->name));
	return true;
}

static inline int listener_filter_chain_match(const Listener__Listener *listener,
					const address_t *addr,
					const ctx_buff_t *ctx,
					Listener__FilterChain **filter_chain_ptr,
					__u64 *filter_chain_idx)
{
	int i;
	void *ptrs = NULL;
	Listener__FilterChain *filter_chain = NULL;

	if (listener->n_filter_chains == 0 || listener->n_filter_chains > KMESH_PER_FILTER_CHAIN_NUM) {
		BPF_LOG(ERR, LISTENER, "listener has no filter chains\n");
		return -1;
	}

	ptrs = kmesh_get_ptr_val(listener->filter_chains);
	if (!ptrs) {
		BPF_LOG(ERR, LISTENER, "failed to get filter chain ptrs\n");
		return -1;
	}

	for (i = 0; i < KMESH_PER_FILTER_CHAIN_NUM; i++) {		
		if (i >= (int)listener->n_filter_chains) {
			break;
		}

		filter_chain = (Listener__FilterChain *)kmesh_get_ptr_val((void*)*((__u64*)ptrs + i));
		if (!filter_chain) {
			continue;
		}

		if (listener_filter_chain_match_check(filter_chain, addr, ctx)) {
			*filter_chain_ptr = filter_chain;
			*filter_chain_idx = (__u64)*((__u64*)ptrs + i);
			return 0;
		}
	}
	return -1;
}

static inline int l7_listener_manager(ctx_buff_t *ctx, Listener__Listener *listener, struct bpf_mem_ptr *msg)
{
	int ret = 0;
	__u64 filter_chain_idx = 0;
	Listener__FilterChain *filter_chain = NULL;
	ctx_key_t ctx_key = {0};
	ctx_val_t ctx_val = {0};

	DECLARE_VAR_ADDRESS(ctx, addr);
	/* filter chain match */
	ret = listener_filter_chain_match(listener, &addr, ctx, &filter_chain, &filter_chain_idx);
	if (ret != 0) {
		BPF_LOG(ERR, LISTENER, "listener_filter_chain_match fail, addr=%u\n", addr.ipv4);
		return -1;
	}
	
	/* exec filter chain */
	ctx_key.address = addr;
	ctx_key.tail_call_index = KMESH_TAIL_CALL_FILTER_CHAIN + bpf_get_current_task();
	ctx_val.val = filter_chain_idx;
	ctx_val.msg = msg;
	ret = kmesh_tail_update_ctx(&ctx_key, &ctx_val);
	if (ret != 0) {
		BPF_LOG(ERR, LISTENER, "kmesh tail update failed:%d\n", ret);
		return ret;
	}

	kmesh_tail_call(ctx, KMESH_TAIL_CALL_FILTER_CHAIN);
	(void)kmesh_tail_delete_ctx(&ctx_key);

	BPF_LOG(ERR, LISTENER, "l7_listener_manager exit\n");
	return ret;
}
#endif
