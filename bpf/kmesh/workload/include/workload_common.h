/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef _WORKLOAD_COMMON_H_
#define _WORKLOAD_COMMON_H_

#include "bpf_log.h"
#include "common.h"
#include "config.h"
#include "workload.h"

#define BPF_LOGTYPE_FRONTEND BPF_DEBUG_ON
#define BPF_LOGTYPE_SERVICE  BPF_DEBUG_ON
#define BPF_LOGTYPE_ENDPOINT BPF_DEBUG_ON
#define BPF_LOGTYPE_BACKEND  BPF_DEBUG_ON
#define BPF_LOGTYPE_AUTH     BPF_DEBUG_ON

// bpf return value
#define CGROUP_SOCK_ERR 0
#define CGROUP_SOCK_OK  1

// loadbalance type
typedef enum {
    LB_POLICY_RANDOM = 0,
    LB_POLICY_STRICT = 1,
    LB_POLICY_FAILOVER = 2,
} lb_policy_t;

#pragma pack(1)
typedef struct {
    __u32 protocol;
    __u32 ipv4;
    __u32 port;
} address_t;
#pragma pack()
#endif // _WORKLOAD_COMMON_H_
