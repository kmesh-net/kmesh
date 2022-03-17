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

#ifndef _ENDPOINT_H_
#define _ENDPOINT_H_

#include "endpoint.pb-c.h"
#include "config.h"

bpf_map_t SEC("maps") map_of_endpoint = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(map_key_t), // come from cluster_t.load_assignment_t or map_of_loadbalance
	.value_size		= sizeof(endpoint_t),
	.max_entries	= MAP_SIZE_OF_ENDPOINT,
	.map_flags		= 0,
};

static inline
endpoint_t *map_lookup_endpoint(const map_key_t *map_key)
{
	return kmesh_map_lookup_elem(&map_of_endpoint, map_key);
}

bpf_map_t SEC("maps") map_of_loadbalance = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(map_key_t), // come from cluster_t.load_assignment_t
	.value_size		= sizeof(loadbalance_t), // select endpoint's map_key next time
	.max_entries	= MAP_SIZE_OF_ENDPOINT,
	.map_flags		= 0,
};

static inline
loadbalance_t *map_lookup_loadbalance(const map_key_t *map_key)
{
	return kmesh_map_lookup_elem(&map_of_loadbalance, map_key);
}

static inline
int map_update_loadbalance(const map_key_t *map_key, const loadbalance_t *value)
{
	return kmesh_map_update_elem(&map_of_loadbalance, map_key, value);
}

#endif // _ENDPOINT_H_