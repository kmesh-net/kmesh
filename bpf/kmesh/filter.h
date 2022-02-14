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

#ifndef _FILTER_H_
#define _FILTER_H_

#include "filter.pb-c.h"
#include "config.h"

bpf_map_t SEC("maps") map_of_filter = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(map_key_t), // come from filter_chain_t
	.value_size		= sizeof(filter_t),
	.max_entries	= MAP_SIZE_OF_FILTER,
	.map_flags		= 0,
};

static inline
filter_t *map_lookup_filter(const map_key_t *map_key)
{
	return kmesh_map_lookup_elem(&map_of_filter, map_key);
}


bpf_map_t SEC("maps") map_of_filter_chain = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(map_key_t), // come from listener_t
	.value_size		= sizeof(filter_chain_t),
	.max_entries	= MAP_SIZE_OF_FILTER_CHAIN,
	.map_flags		= 0,
};

static inline
filter_chain_t *map_lookup_filter_chain(const map_key_t *map_key)
{
	return kmesh_map_lookup_elem(&map_of_filter_chain, map_key);
}

static inline
int filter_chain_match_check(ctx_buff_t *ctx, filter_chain_match_t *filter_chain_match)
{
	//TODO
	return 0;
}

#endif //_FILTER_H_
