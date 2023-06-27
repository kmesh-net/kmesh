/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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

 * Author: nlgwcy
 * Create: 2022-02-14
 */
#ifndef __KMESH_FILTER_H__
#define __KMESH_FILTER_H__

#include "kmesh_common.h"
#include "listener/listener.pb-c.h"
#include "filter/tcp_proxy.pb-c.h"
#include "filter/http_connection_manager.pb-c.h"


static inline int filter_match_check(const Listener__Filter *filter, const address_t *addr, const ctx_buff_t *ctx)
{
	int match = 0;
	switch (filter->config_type_case) {
		case LISTENER__FILTER__CONFIG_TYPE_HTTP_CONNECTION_MANAGER:
			match = 1;
			break;
		case LISTENER__FILTER__CONFIG_TYPE_TCP_PROXY:
			match = 1;
			break;
		default:
			break;
	}
	return match;
}

static inline int filter_chain_filter_match(const Listener__FilterChain *filter_chain,
											 const address_t *addr,
											 const ctx_buff_t *ctx,
											 Listener__Filter **filter_ptr,
											 __u64 *filter_ptr_idx)
{
	void *ptrs = NULL;
	Listener__Filter *filter = NULL;

	if (!filter_ptr || !filter_ptr_idx) {
		BPF_LOG(ERR, FILTERCHAIN, "invalid params\n");
		return -1;
	}

	if (filter_chain->n_filters == 0 || filter_chain->n_filters > KMESH_PER_FILTER_NUM) {
		BPF_LOG(ERR, FILTERCHAIN, "nfilter num(%d) invalid\n", filter_chain->n_filters);
		return -1;
	}
	
	/* filter match */
	ptrs = kmesh_get_ptr_val(filter_chain->filters);
	if (!ptrs) {
		BPF_LOG(ERR, FILTER, "failed to get filter ptrs\n");
		return -1;
	}

	/* limit loop cap to pass bpf verify */
	for (unsigned int i = 0; i < KMESH_PER_FILTER_NUM; i++) {
		if (i >= filter_chain->n_filters) {
			break;
		}

		filter = (Listener__Filter *)kmesh_get_ptr_val((void*)*((__u64*)ptrs + i));
		if (!filter) {
			continue;
		}

		// FIXME: repeat on filter_manager
		if (filter_match_check(filter, addr, ctx)) {
			*filter_ptr = filter;
			*filter_ptr_idx = (__u64)*((__u64 *)ptrs + i);
			return 0;
		}
	}
	return -1;
}
#endif
