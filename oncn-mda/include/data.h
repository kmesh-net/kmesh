/*
 * Copyright 2023 The Kmesh Authors.
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
 *
 * Description: this file used by ebpf and cli param struct define
 */

#ifndef SOCK_MESH_ACCELERATE_DATA_H
#define SOCK_MESH_ACCELERATE_DATA_H

#include <linux/bpf.h>
#include "../../config/kmesh_marcos_def.h"

#define SKOPS_MAP_SIZE   196608
#define MAX_PARAM_LENGTH 10

#define DUMP_QUEUE_LENGTH  4096
#define MAX_DUMP_DATA_SIZE 4096

#define SUCCESS 0
#define FAILED  1

#define TRUE  0
#define FALSE 1

#define ERROR (-1)

// Currently, the maximum length of the NAME of BPF Map prog can be defined as 16(including '\0'),
// which will be truncated
#define SOCK_OPS_MAP_NAME        sock_ops_map
#define SOCK_PARAM_MAP_NAME      sock_param_map
#define SOCK_OPS_PROXY_MAP_NAME  sock_proxy_map
#define SOCK_DUMP_MAP_I_NAME     sock_dump_map
#define SOCK_DUMP_CPU_ARRAY_NAME sock_ddata_map

#if MDA_GID_UID_FILTER
#define MAX_UID_GID_LENGTH       10
#define SOCK_OPS_HELPER_MAP_NAME sock_helper_map
#endif

#define SOCK_OPS_NAME      ma_ops
#define SOCK_REDIRECT_NAME ma_redirect

#define to_str__(X) #X
#define to_str(X)   to_str__(X)

struct sock_key {
    __u32 sip4;
    __u32 dip4;
    __u32 sport;
    __u32 dport;
#if MDA_LOOPBACK_ADDR
    __u64 netns_cookie;
#endif
} __attribute__((packed));

struct cidr {
    __u32 ip4;
    __u32 mask;
} __attribute__((packed));

struct port_range {
    __u32 begin_port;
    __u32 end_port;
} __attribute__((packed));

struct dump_prarm {
    __u32 switch_on;
    __u8 current_cidr_num; // Indicates the number of cidRs currently entered
    __u8 current_port_num; // Indicates the number of ports to be filtered
    struct cidr dump_cidr[MAX_PARAM_LENGTH];
    struct port_range dump_port[MAX_PARAM_LENGTH];
} __attribute__((packed));
// When modifying the following structure, place PARAM_SIZE last
enum ma_param_type {
    ACCEPT_IP = 0,
    RETURN_IP,
    ACCEPT_PORT,
    RETURN_PORT,
#if MDA_GID_UID_FILTER
    ACCEPT_UID,
    RETURN_UID,
    ACCEPT_GID,
    RETURN_GID,
#endif
    DUMP,
    DUMP_IP,
    DUMP_PORT,
    PARAM_SIZE,
};

struct input_cidr {
    __u8 current_cidr_num;
    struct cidr cidrs[MAX_PARAM_LENGTH];
} __attribute__((packed));

struct input_port {
    __u8 current_port_num;
    struct port_range ports[MAX_PARAM_LENGTH];
} __attribute__((packed));

#if MDA_GID_UID_FILTER
struct uid_gid_info {
    __u32 cuid;
    __u32 cgid;
    __u32 puid;
    __u32 pgid;
} __attribute__((packed));

struct input_uid {
    __u8 current_uid_num;
    __u32 uids[MAX_PARAM_LENGTH];
} __attribute__((packed));

struct input_gid {
    __u8 current_gid_num;
    __u32 gids[MAX_PARAM_LENGTH];
} __attribute__((packed));
#endif

struct sock_param {
    struct input_cidr accept_cidrs;
    struct input_cidr return_cidrs;
    struct input_port accept_ports;
    struct input_port return_ports;
#if MDA_GID_UID_FILTER
    struct input_uid accept_uids;
    struct input_uid return_uids;
    struct input_gid accept_gids;
    struct input_gid return_gids;
#endif
    struct dump_prarm dump_params;
} __attribute__((packed));

struct dump_data {
    __u64 timestamp;
    __u32 sip;
    __u32 sport;
    __u32 dip;
    __u32 dport;
    __u32 data_length;
};

#endif
