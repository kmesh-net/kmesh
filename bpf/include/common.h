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

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "errno.h"

#define bpf_unused __attribute__((__unused__))

#define BPF_MAX(x , y)		(((x) > (y)) ? (x) : (y))
#define BPF_MIN(x , y)		(((x) < (y)) ? (x) : (y))

#ifndef bpf_memset
#define bpf_memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef bpf_memcpy
#define bpf_memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

typedef struct bpf_map_def bpf_map_t;

static inline
void *kmesh_map_lookup_elem(bpf_map_t *map, const void *key)
{
	return bpf_map_lookup_elem(map, key);
}

static inline
int kmesh_map_delete_elem(bpf_map_t *map, const void *key)
{
	return bpf_map_delete_elem(map, key);
}

static inline
int kmesh_map_update_elem(bpf_map_t *map, const void *key, const void *value)
{
	// TODO: 重复元素，状态更新
	return bpf_map_update_elem(map, key, value, BPF_ANY);
}

#endif //_COMMON_H_
