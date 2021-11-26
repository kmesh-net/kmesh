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

#ifndef _CLUSTER_H_
#define _CLUSTER_H_

#include "cluster_type.h"

bpf_map_t SEC("maps") map_of_cluster = {
	.type			= BPF_MAP_TYPE_HASH,
	// come from listener_t or route_action_t
	.key_size		= sizeof(map_key_t),
	.value_size		= sizeof(cluster_t),
	.max_entries	= MAP_SIZE_OF_CLUSTER,
	.map_flags		= 0,
};

static inline
cluster_t *map_lookup_cluster(map_key_t *map_key)
{
	return kmesh_map_lookup_elem(&map_of_cluster, map_key);
}

bpf_map_t SEC("maps") map_of_loadbanance = {
	.type			= BPF_MAP_TYPE_HASH,
	// come from cluster_t
	.key_size		= sizeof(map_key_t),
	// selecte endpoint's map_key next time
	.value_size		= sizeof(map_key_t),
	.max_entries	= MAP_SIZE_OF_CLUSTER,
	.map_flags		= 0,
};

static inline
map_key_t *map_lookup_loadbanance(map_key_t *map_key)
{
	return kmesh_map_lookup_elem(&map_of_loadbanance, map_key);
}

static inline
int map_update_loadbanance(map_key_t *map_key, map_key_t *value)
{
	return kmesh_map_update_elem(&map_of_loadbanance, map_key, value);
}

#endif //_CLUSTER_H_
