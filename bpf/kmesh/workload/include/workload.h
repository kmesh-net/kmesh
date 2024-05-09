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

#ifndef __KMESH_WORKLOAD_H__
#define __KMESH_WORKLOAD_H__

#include "config.h"

#define MAX_PORT_COUNT 10
#define RINGBUF_SIZE   (1 << 12)

// frontend map
typedef struct {
    __u32 ipv4; // Service ip or Pod ip
} __attribute__((packed)) frontend_key;

typedef struct {
    __u32 upstream_id; // service id for Service access or backend uid for Pod access
} __attribute__((packed)) frontend_value;

// service map
typedef struct {
    __u32 service_id; // service id
} __attribute__((packed)) service_key;

typedef struct {
    __u32 endpoint_count; // endpoint count of current service
    __u32 lb_policy;      // load balancing algorithm, currently only supports random algorithm
} __attribute__((packed)) service_value;

// endpoint map
typedef struct {
    __u32 service_id;    // service id
    __u32 backend_index; // if endpoint_count = 3, then backend_index = 0/1/2
} __attribute__((packed)) endpoint_key;

typedef struct {
    __u32 backend_uid; // workload_uid to uint32
} __attribute__((packed)) endpoint_value;

// backend map
typedef struct {
    __u32 backend_uid; // workload_uid to uint32
} __attribute__((packed)) backend_key;

typedef struct {
    __u32 ipv4; // backend ip
    __u32 port_count;
    __u32 service_port[MAX_PORT_COUNT];
    __u32 target_port[MAX_PORT_COUNT];
    __u32 waypoint_addr;
    __u32 waypoint_port;
} __attribute__((packed)) backend_value;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(frontend_key));
    __uint(value_size, sizeof(frontend_value));
    __uint(max_entries, MAP_SIZE_OF_FRONTEND);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_of_frontend SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(service_key));
    __uint(value_size, sizeof(service_value));
    __uint(max_entries, MAP_SIZE_OF_SERVICE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_of_service SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(endpoint_key));
    __uint(value_size, sizeof(endpoint_value));
    __uint(max_entries, MAP_SIZE_OF_ENDPOINT);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_of_endpoint SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(backend_key));
    __uint(value_size, sizeof(backend_value));
    __uint(max_entries, MAP_SIZE_OF_BACKEND);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_of_backend SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bpf_sock_tuple);
    __type(value, __u32);
    __uint(max_entries, MAP_SIZE_OF_AUTH);
} map_of_auth SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} map_of_tuple SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, MAP_SIZE_OF_MANAGER);
    __uint(map_flags, 0);
} map_of_manager SEC(".maps");
#endif
