/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __KMESH_IPSEC_H__
#define __KMESH_IPSEC_H__
#include <linux/bpf.h>
#include "common.h"
#include "map_config.h"

#define MAP_SIZE_OF_NODEINFO 8192

struct lpm_key {
    struct bpf_lpm_trie_key trie_key;
    struct ip_addr ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_NODEINFO);
} map_of_nodeinfo SEC(".maps");

#endif /* __KMESH_IPSEC_H__ */