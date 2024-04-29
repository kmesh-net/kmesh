/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 * Author: kwb0523
 * Create: 2024-01-20
 */

#ifndef _WORKLOAD_COMMON_H_
#define _WORKLOAD_COMMON_H_

#include "bpf_log.h"
#include "common.h"
#include "config.h"
#include "workload.h"

#define KMESH_CLASSID_MARK 0x1000

#define BPF_LOGTYPE_FRONTEND BPF_DEBUG_OFF
#define BPF_LOGTYPE_SERVICE  BPF_DEBUG_OFF
#define BPF_LOGTYPE_ENDPOINT BPF_DEBUG_OFF
#define BPF_LOGTYPE_BACKEND  BPF_DEBUG_OFF

// bpf return value
#define CGROUP_SOCK_ERR 0
#define CGROUP_SOCK_OK  1

// loadbalance type
typedef enum {
    LB_POLICY_RANDOM = 0,
} lb_policy_t;

typedef struct {
    __u32 protocol;
    __u32 ipv4;
    __u32 port;
} __attribute__((packed)) address_t;

#endif // _WORKLOAD_COMMON_H_
