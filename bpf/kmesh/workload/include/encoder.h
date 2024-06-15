/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __ENCODER_H__
#define __ENCODER_H__

#include "config.h"
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct bpf_sock_tuple);
    __uint(max_entries, MAP_SIZE_OF_DSTINFO);
    __uint(map_flags, 0);
} map_of_dst_info SEC(".maps");

#endif /*__ENCODER_H__*/