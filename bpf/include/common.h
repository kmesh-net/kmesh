/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef _COMMON_H_
#define _COMMON_H_

#include "../../config/kmesh_marcos_def.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "errno.h"

#if ENHANCED_KERNEL
#include <bpf_helper_defs_ext.h>
#endif

#define bpf_unused __attribute__((__unused__))

#define BPF_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define BPF_MIN(x, y) (((x) < (y)) ? (x) : (y))

#ifndef bpf_memset
#define bpf_memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif

#ifndef bpf_memcpy
#define bpf_memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef __stringify
#define __stringify(X) #X
#endif
#define SEC_TAIL(ID, KEY) SEC(__stringify(ID) "/" __stringify(KEY))

struct ip_addr {
    union {
        __u32 ip4;
        __u32 ip6[4];
    };
};
#define IPV6_ADDR_LEN 16


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

#if OE_23_03
#define bpf__strncmp                  bpf_strncmp
#define GET_SKOPS_REMOTE_PORT(sk_ops) (__u16)((sk_ops)->remote_port)
#else
#define GET_SKOPS_REMOTE_PORT(sk_ops) (__u16)((sk_ops)->remote_port >> 16)
#endif

#define GET_SKOPS_LOCAL_PORT(sk_ops) (__u16)((sk_ops)->local_port)

#endif // _COMMON_H_
