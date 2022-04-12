/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *	 http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2021-09-17
 */

#ifndef _TC_REV_NAT_H_
#define _TC_REV_NAT_H_

#include "common.h"
#include "config.h"
#include "address.pb-c.h"
#define PIN_GLOBAL_NS		2

struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
};
struct bpf_elf_map SEC("maps") map_of_tuple_ct = {
		.type			= BPF_MAP_TYPE_HASH,
		.size_key		= sizeof(tuple_t),
		.size_value		= sizeof(address_t),
		.max_elem	= MAP_SIZE_OF_ENDPOINT,
		.pinning		= PIN_GLOBAL_NS,
};

static inline address_t* map_lookup_tuple_in_tc(const tuple_t* tuple)
{
	return bpf_map_lookup_elem(&map_of_tuple_ct, tuple);
}

#endif // _TUPLE_H_