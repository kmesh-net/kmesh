/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

/*
 * Note: when compiling kmesh, the helper function IDs listed in this
 * file will be updated based on the file "/usr/include/linux/bpf.h"
 * in the compilation environment. In addition, newly developed helper
 * functions will also be added here in the future.
 *
 * By default, these IDs are in the 5.10 kernel with kmesh kernel patches.
 */

static void *(*bpf_strncpy)(char *dst, __u32 dst_size, char *src) = (void *)171;
static void *(*bpf_strnstr)(void *s1, void *s2, __u32 size) = (void *)172;
static __u64 (*bpf_strnlen)(char *buff, __u32 size) = (void *)173;
static __u64 (*bpf__strncmp)(const char *s1, __u32 s1_size, const char *s2) = (void *)174;
static long (*bpf_parse_header_msg)(struct bpf_mem_ptr *msg) = (void *)175;
static void *(*bpf_get_msg_header_element)(void *name) = (void *)176;
