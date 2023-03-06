/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
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
