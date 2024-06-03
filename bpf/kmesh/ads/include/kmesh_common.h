/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef _KMESH_COMMON_H_
#define _KMESH_COMMON_H_

#include "bpf_log.h"
#include "common.h"
#include "config.h"
#include "core/address.pb-c.h"

#define BPF_LOGTYPE_LISTENER      BPF_DEBUG_OFF
#define BPF_LOGTYPE_FILTERCHAIN   BPF_DEBUG_OFF
#define BPF_LOGTYPE_FILTER        BPF_DEBUG_OFF
#define BPF_LOGTYPE_CLUSTER       BPF_DEBUG_OFF
#define BPF_LOGTYPE_ROUTER        BPF_DEBUG_OFF
#define BPF_LOGTYPE_ROUTER_CONFIG BPF_DEBUG_OFF
#define BPF_LOGTYPE_COMMON        BPF_DEBUG_OFF

#define BPF_DATA_MAX_LEN                                                                                               \
    192 /* this value should be                                                                                        \
small that make compile success */
#define BPF_INNER_MAP_DATA_LEN 1300

#define BPF_OK 1

#define _(P)                                                                                                           \
    ({                                                                                                                 \
        typeof(P) val;                                                                                                 \
        bpf_probe_read_kernel(&val, sizeof(val), &P);                                                                  \
        val;                                                                                                           \
    })

struct bpf_mem_ptr {
    void *ptr;
    __u32 size;
};

#if !ENHANCED_KERNEL
static inline int bpf__strncmp(char *dst, int n, const char *src)
{
    if (dst == NULL || src == NULL)
        return -1;

#pragma unroll
    for (int i = 0; i < BPF_DATA_MAX_LEN; i++) {
        if (dst[i] != src[i])
            return dst[i] - src[i];
        else if (dst[i] == '\0' || i == n - 1)
            return 0;
    }
    return 0;
};

static inline char *bpf_strncpy(char *dst, int n, const char *src)
{
    int isEnd = 0;
    if (src == NULL)
        return 0;

#pragma unroll
    for (int i = 0; i < BPF_DATA_MAX_LEN; i++) {
        if (src[i] == '\0')
            isEnd = 1;
        if (isEnd == 1)
            dst[i] = '\0';
        else
            dst[i] = src[i];
        if (i == n - 1)
            break;
    }
    return dst;
}
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAP_SIZE_OF_OUTTER_MAP);
    __uint(map_flags, 0);
} outer_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, BPF_INNER_MAP_DATA_LEN);
    __uint(max_entries, 1);
    __uint(map_flags, 0);
} inner_map SEC(".maps");

typedef enum {
    KMESH_TAIL_CALL_LISTENER = 1,
    KMESH_TAIL_CALL_FILTER_CHAIN,
    KMESH_TAIL_CALL_FILTER,
    KMESH_TAIL_CALL_ROUTER,
    KMESH_TAIL_CALL_CLUSTER,
    KMESH_TAIL_CALL_ROUTER_CONFIG,
} tail_call_index_t;

typedef Core__SocketAddress address_t;

// bpf return value
#define CGROUP_SOCK_ERR 0
#define CGROUP_SOCK_OK  1

enum kmesh_l7_proto_type { PROTO_UNKNOW = 0, PROTO_HTTP_1_1, PROTO_HTTP_2_0 };

enum kmesh_l7_msg_type { MSG_UNKNOW = 0, MSG_REQUEST, MSG_MID_REPONSE, MSG_FINAL_RESPONSE };

#define KMESH_PROTO_TYPE_WIDTH (8)
#define GET_RET_PROTO_TYPE(n)  ((n)&0xff)
#define GET_RET_MSG_TYPE(n)    (((n) >> KMESH_PROTO_TYPE_WIDTH) & 0xff)

static inline void *kmesh_get_ptr_val(const void *ptr)
{
    /*
        map_in_map -- outer_map:
        key		value
        idx1	inner_map_fd1	// point to inner map1
        idx2	 inner_map_fd2	// point to inner map2

        structA.ptr_member1 = idx1;	// store idx in outer_map
    */
    void *inner_map_instance = NULL;
    __u32 inner_idx = 0;
    __u64 idx = (__u64)ptr;

    BPF_LOG(DEBUG, COMMON, "kmesh_get_ptr_val idx=%u\n", idx);
    if (!ptr) {
        return NULL;
    }

    /* get inner_map_instance by idx */
    inner_map_instance = kmesh_map_lookup_elem(&outer_map, &idx);
    if (!inner_map_instance) {
        return NULL;
    }

    /* get inner_map_instance value */
    return kmesh_map_lookup_elem(inner_map_instance, &inner_idx);
}
#endif // _KMESH_COMMON_H_
