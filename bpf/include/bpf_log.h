/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef _BPF_LOG_H_
#define _BPF_LOG_H_

#include "common.h"

#define BPF_DEBUG_ON  0
#define BPF_DEBUG_OFF (-1)

#define BPF_LOG_LEVEL BPF_LOG_DEBUG

#define BPF_LOGTYPE_SOCKMAP BPF_DEBUG_OFF
#define BPF_LOGTYPE_KMESH   BPF_DEBUG_ON
#define BPF_LOGTYPE_SOCKOPS BPF_DEBUG_OFF
#define BPF_LOGTYPE_XDP     BPF_DEBUG_OFF
#define BPF_LOGTYPE_SENDMSG BPF_DEBUG_OFF
#define MAX_MSG_LEN         255

enum bpf_loglevel {
    BPF_LOG_ERR = 0,
    BPF_LOG_WARN,
    BPF_LOG_INFO,
    BPF_LOG_DEBUG,
};

struct log_event {
    __u32 ret;
    char msg[MAX_MSG_LEN];
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} kmesh_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct log_event);
} heap SEC(".maps");

#define BPF_LOG(l, t, f, ...)                                                                                          \
    do {                                                                                                               \
        int loglevel = BPF_MIN((int)BPF_LOG_LEVEL, ((int)BPF_LOG_DEBUG + (int)(BPF_LOGTYPE_##t)));                     \
        if ((int)(BPF_LOG_##l) <= loglevel) {                                                                          \
            char fmt[] = "[" #t "] " #l ": " f "";                                                                     \
            bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__);                                                         \
        }                                                                                                              \
    } while (0)

/* Add this macro to get ip addr from ctx variable, include bpf_sock_addr or bpf_sock_ops, weird
reason is direct access would not be print ipaddr when pass `&ctx->remote_ipv4` to bpf_trace_printk */
#define DECLARE_VAR_IPV4(ctx_ip, name)                                                                                 \
    __u32 name = 0;                                                                                                    \
    name = ctx_ip;

#define Kmesh_BPF_SNPRINTF(out, out_size, fmt, args...)                                                                \
    ({                                                                                                                 \
        unsigned long long ___param[___bpf_narg(args)];                                                                \
                                                                                                                       \
        _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")                          \
            ___bpf_fill(___param, args);                                                                               \
        _Pragma("GCC diagnostic pop")                                                                                  \
                                                                                                                       \
            bpf_snprintf(out, out_size, fmt, ___param, sizeof(___param));                                              \
    })

#define BPF_LOG_U(l, t, f, args...)                                                                                    \
    do {                                                                                                               \
        int loglevel = BPF_MIN((int)BPF_LOG_LEVEL, ((int)BPF_LOG_DEBUG + (int)(BPF_LOGTYPE_##t)));                     \
        if ((int)(BPF_LOG_##l) <= loglevel) {                                                                          \
            static const char fmt[] = "[" #t "] " #l ": " f "";                                                        \
            struct log_event *e;                                                                                       \
            __u32 ret = 0;                                                                                             \
            int zero = 0;                                                                                              \
            e = bpf_map_lookup_elem(&heap, &zero);                                                                     \
            if (!e)                                                                                                    \
                break;                                                                                                 \
            ret = Kmesh_BPF_SNPRINTF(e->msg, sizeof(e->msg), fmt, args);                                               \
            e->ret = ret;                                                                                              \
            if (ret < 0)                                                                                               \
                break;                                                                                                 \
            bpf_ringbuf_output(&kmesh_events, e, sizeof(*e), 0);                                                       \
        }                                                                                                              \
    } while (0)

#endif // _BPF_LOG_H_
