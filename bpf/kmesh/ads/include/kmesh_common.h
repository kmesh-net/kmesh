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

#define BPF_LOGTYPE_LISTENER        BPF_DEBUG_ON
#define BPF_LOGTYPE_FILTERCHAIN     BPF_DEBUG_ON
#define BPF_LOGTYPE_FILTER          BPF_DEBUG_ON
#define BPF_LOGTYPE_CLUSTER         BPF_DEBUG_ON
#define BPF_LOGTYPE_ROUTER          BPF_DEBUG_ON
#define BPF_LOGTYPE_ROUTER_CONFIG   BPF_DEBUG_ON
#define BPF_LOGTYPE_COMMON          BPF_DEBUG_ON
#define BPF_LOGTYPE_CIRCUIT_BREAKER BPF_DEBUG_ON

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
