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

 * Author: kwb0523
 * Create: 2024-01-20
 */
#ifndef __ROUTE_BACKEND_H__
#define __ROUTE_BACKEND_H__

#include "workload_common.h"

static inline backend_value *map_lookup_backend(const backend_key *key)
{
	return kmesh_map_lookup_elem(&map_of_backend, key);
}

static inline int backend_manager(ctx_buff_t *ctx, backend_value *backend_v)
{
	address_t target_addr;

	DECLARE_VAR_ADDRESS(ctx, address);
	#pragma unroll
	for (unsigned int i = 0; i < backend_v->port_count; i++) {
		if (i >= MAX_PORT_COUNT) {
			BPF_LOG(ERR, BACKEND, "exceed the max port count\n");
			return -EINVAL;
		}

		if (address.service_port == backend_v->service_port[i]) {
			target_addr.ipv4 = backend_v->ipv4;
			target_addr.port = backend_v->target_port[i];
			SET_CTX_ADDRESS(ctx, target_addr);
			BPF_LOG(DEBUG, BACKEND, "get the backend addr=[%u:%u]\n", 
				target_addr.ipv4, target_addr.port);
			return 0;
		}
	}

	BPF_LOG(ERR, BACKEND, "failed to get the backend\n");
	return -ENOENT;
}

#endif

