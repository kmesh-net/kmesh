/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __KMESH_WORKLOAD_H__
#define __KMESH_WORKLOAD_H__

#include "config.h"

#define MAX_PORT_COUNT    10
#define MAX_SERVICE_COUNT 10
#define RINGBUF_SIZE      (1 << 12)

// frontend map
typedef struct {
    struct ip_addr addr; // Service ip or Pod ip
} __attribute__((packed)) frontend_key;

typedef struct {
    __u32 upstream_id; // service id for Service access or backend uid for Pod access
} __attribute__((packed)) frontend_value;

// service map
typedef struct {
    __u32 service_id; // service id
} __attribute__((packed)) service_key;

typedef struct {
    __u32 endpoint_count;               // endpoint count of current service
    __u32 lb_policy;                    // load balancing algorithm, currently only supports random algorithm
    __u32 service_port[MAX_PORT_COUNT]; // service_port[i] and target_port[i] are a pair, i starts from 0 and max value
                                        // is MAX_PORT_COUNT-1
    __u32 target_port[MAX_PORT_COUNT];
    struct ip_addr wp_addr;
    __u32 waypoint_port;
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
    struct ip_addr addr;
    __u32 service_count;
    __u32 service[MAX_SERVICE_COUNT];
    struct ip_addr wp_addr;
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

#endif
