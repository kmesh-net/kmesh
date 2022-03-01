/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
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
#ifndef __KMESH_FILTER_H__
#define __KMESH_FILTER_H__

#include "kmesh_common.h"
#include "listener/listener.pb-c.h"
#include "filter/tcp_proxy.pb-c.h"
#include "filter/http_connection_manager.pb-c.h"


static inline
int filter_match_check(const Listener__Filter *filter, const address_t *addr, const ctx_buff_t *ctx)
{
	int match = 0;
	switch (filter->config_type_case) {
		case LISTENER__FILTER__CONFIG_TYPE_HTTP_CONNECTION_MANAGER:
			match = 1;
			break;
		case LISTENER__FILTER__CONFIG_TYPE_TCP_PROXY:
			break;
		default:
			break;
	}
	return match;
}

static inline
int filter_chain_filter_match(const Listener__FilterChain *filter_chain, 
											 const address_t *addr, 
											 const ctx_buff_t *ctx,
											 Listener__Filter **filter_ptr,
											 __u64 *filter_ptr_idx)
{
	int i;
	void *ptrs = NULL;
	size_t nfilter = filter_chain->n_filters;
	Listener__Filter *filter = NULL;
	
	BPF_LOG(INFO, FILTERCHAIN, "enter filter_chain_filter_match\n");

	if (!filter_ptr || !filter_ptr_idx) {
		BPF_LOG(ERR, FILTERCHAIN, "invalid params\n");
		return -1;
	}

	if (nfilter == 0 || nfilter > KMESH_PER_FILTER_NUM) {
		BPF_LOG(ERR, FILTERCHAIN, "nfilter num(%d) invalid\n", nfilter);
		return -1;
	}
	
	/* filter match */
	ptrs = kmesh_get_ptr_val(filter_chain->filters);
	if (!ptrs) {
		BPF_LOG(ERR, FILTER, "failed to get filter ptrs\n");
		return -1;
	}

	/* limit loop cap to pass bpf verify */
	nfilter = BPF_MIN(nfilter, KMESH_PER_FILTER_NUM);
#pragma unroll
	for (i = 0; i < nfilter; i++) {
		filter = (Listener__Filter *)kmesh_get_ptr_val(_(ptrs + i));
		if (!filter) {
			continue;
		}

		if (filter_match_check(filter, addr, ctx)) {
			*filter_ptr = filter;
			*filter_ptr_idx = (__u64)_(ptrs + i);
			return 0;
		}
	}
	return -1;
}

#endif