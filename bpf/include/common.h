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

#define BPF_MAX(x , y)		(((x) > (y)) ? (x) : (y))
#define BPF_MIN(x , y)		(((x) < (y)) ? (x) : (y))

typedef struct {
	char name[KMESH_NAME_LEN];
} key_name_t;

typedef struct {
	__u16 index;
	char name[KMESH_NAME_LEN];
} key_array_t;

typedef struct {
	__u16 count;
	__u16 capacity;
} key_index_t;

#endif //_COMMON_H_
