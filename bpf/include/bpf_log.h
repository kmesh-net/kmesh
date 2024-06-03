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
enum bpf_loglevel {
    BPF_LOG_ERR = 0,
    BPF_LOG_WARN,
    BPF_LOG_INFO,
    BPF_LOG_DEBUG,
};

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

#endif // _BPF_LOG_H_
