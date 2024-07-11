/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef _KMESH_COMMON_H_
#define _KMESH_COMMON_H_

#include "bpf_log.h"
#include "common.h"
#include "bpf_common.h"
#include "config.h"
#include "core/address.pb-c.h"
#include "tail_call_index.h"

#define BPF_LOGTYPE_LISTENER      BPF_DEBUG_ON
#define BPF_LOGTYPE_FILTERCHAIN   BPF_DEBUG_ON
#define BPF_LOGTYPE_FILTER        BPF_DEBUG_ON
#define BPF_LOGTYPE_CLUSTER       BPF_DEBUG_ON
#define BPF_LOGTYPE_ROUTER        BPF_DEBUG_ON
#define BPF_LOGTYPE_ROUTER_CONFIG BPF_DEBUG_ON
#define BPF_LOGTYPE_COMMON        BPF_DEBUG_ON

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
static inline int bpf__strncmp(const char *dst, int n, const char *src)
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

struct cluster_sock_data {
    char cluster_name[BPF_DATA_MAX_LEN];
};

struct resource {
    // current value
    __u64 curr;
    __u64 max;
};

struct cluster_resources {
    struct resource connections;
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct cluster_sock_data);
} map_of_cluster_sock SEC(".maps");

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

#endif // _KMESH_COMMON_H_
