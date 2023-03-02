/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
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

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <bpf_helper_defs_ext.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "errno.h"

#define bpf_unused __attribute__((__unused__))

#define BPF_MAX(x, y)		(((x) > (y)) ? (x) : (y))
#define BPF_MIN(x, y)		(((x) < (y)) ? (x) : (y))

#ifndef bpf_memset
#define bpf_memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef bpf_memcpy
#define bpf_memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef __stringify
#define __stringify(X)					#X
#endif
#define SEC_TAIL(ID, KEY)				SEC(__stringify(ID) "/" __stringify(KEY))

static inline void *kmesh_map_lookup_elem(void *map, const void *key)
{
	return bpf_map_lookup_elem(map, key);
}

static inline int kmesh_map_delete_elem(void *map, const void *key)
{
	return (int)bpf_map_delete_elem(map, key);
}

static inline int kmesh_map_update_elem(void *map, const void *key, const void *value)
{
	// TODO: Duplicate element, status update
	return (int)bpf_map_update_elem(map, key, value, BPF_ANY);
}

#endif // _COMMON_H_
