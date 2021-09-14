/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stddef.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "config.h"

#define bpf_unused __attribute__((__unused__))

#define BPF_MAX(x , y)		(((x) > (y)) ? (x) : (y))
#define BPF_MIN(x , y)		(((x) < (y)) ? (x) : (y))

// https://maao.cloud/2021/03/01/%E7%AC%94%E8%AE%B0-BPF-and-XDP-Reference-Guide-cilium/
#ifndef bpf_memset
#define bpf_memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef bpf_memcpy
#define bpf_memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

typedef struct bpf_map_def bpf_map_t;

typedef struct {
	__u16 index;
	char name[KMESH_NAME_LEN];
} key_array_t;

typedef struct {
	__u16 count;
	__u16 capacity;
} key_index_t;

static inline
void kmesh_map_get_key(char *name, bpf_unused unsigned len, unsigned index, key_array_t *key)
{
	key->index = index;
	// len must be a constant?
	(void)bpf_memcpy(key->name, name, KMESH_NAME_LEN);
}

static inline
void *kmesh_map_get_elem(bpf_map_t *map, const key_array_t *key)
{
	return bpf_map_lookup_elem(map, key);
}

static inline
int kmesh_map_del_elem(bpf_map_t *map, const key_array_t *key)
{
	return bpf_map_delete_elem(map, key);
}

static inline
int kmesh_map_add_elem(bpf_map_t *map, const key_array_t *key, const void *value)
{
	// TODO: 重复元素，状态更新
	return bpf_map_update_elem(map, key, value, BPF_ANY);
}

typedef struct {
	void (*map_get_key)(char *name, unsigned len, unsigned index, key_array_t *key);
	void *(*map_get_elem)(bpf_map_t *map, const key_array_t *key);
	int (*map_del_elem)(bpf_map_t *map, const key_array_t *key);
	int (*map_add_elem)(bpf_map_t *map, const key_array_t *key, const void *value);
} map_ops_t;

const map_ops_t kmesh_map_ops = {
	.map_get_key  = kmesh_map_get_key,
	.map_get_elem = kmesh_map_get_elem,
	.map_del_elem = kmesh_map_del_elem,
	.map_add_elem = kmesh_map_add_elem,
};

#endif //_COMMON_H_
