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

 * Author: nlgwcy
 * Create: 2022-02-17
 */

#ifndef _KMESH_CONFIG_H_
#define _KMESH_CONFIG_H_

// ************
// options
#define KMESH_MODULE_ON  1
#define KMESH_MODULE_OFF 0

// L3
#define KMESH_ENABLE_IPV4 KMESH_MODULE_ON
#define KMESH_ENABLE_IPV6 KMESH_MODULE_OFF
// L4
#define KMESH_ENABLE_TCP KMESH_MODULE_ON
#define KMESH_ENABLE_UDP KMESH_MODULE_OFF
// L7
#define KMESH_ENABLE_HTTP  KMESH_MODULE_ON
#define KMESH_ENABLE_HTTPS KMESH_MODULE_OFF

// ************
// map size
#define MAP_SIZE_OF_PER_LISTENER     64
#define MAP_SIZE_OF_PER_FILTER_CHAIN 4
#define MAP_SIZE_OF_PER_FILTER       4
#define MAP_SIZE_OF_PER_VIRTUAL_HOST 16
#define MAP_SIZE_OF_PER_ROUTE        8
#define MAP_SIZE_OF_PER_CLUSTER      32
#define MAP_SIZE_OF_PER_ENDPOINT     64
#define MAP_SIZE_OF_MANAGER          8192

#define MAP_SIZE_OF_MAX 8192

#define MAP_SIZE_OF_LISTENER     BPF_MIN(MAP_SIZE_OF_MAX, MAP_SIZE_OF_PER_LISTENER)
#define MAP_SIZE_OF_FILTER_CHAIN BPF_MIN(MAP_SIZE_OF_MAX, MAP_SIZE_OF_PER_FILTER_CHAIN *MAP_SIZE_OF_LISTENER)
#define MAP_SIZE_OF_FILTER       BPF_MIN(MAP_SIZE_OF_MAX, MAP_SIZE_OF_PER_FILTER *MAP_SIZE_OF_FILTER_CHAIN)
#define MAP_SIZE_OF_VIRTUAL_HOST BPF_MIN(MAP_SIZE_OF_MAX, MAP_SIZE_OF_PER_VIRTUAL_HOST *MAP_SIZE_OF_FILTER)
#define MAP_SIZE_OF_ROUTE        BPF_MIN(MAP_SIZE_OF_MAX, MAP_SIZE_OF_PER_ROUTE *MAP_SIZE_OF_VIRTUAL_HOST)
#define MAP_SIZE_OF_CLUSTER      BPF_MIN(MAP_SIZE_OF_MAX, MAP_SIZE_OF_PER_CLUSTER *MAP_SIZE_OF_ROUTE)
#define MAP_SIZE_OF_ENDPOINT     BPF_MIN(MAP_SIZE_OF_MAX, MAP_SIZE_OF_PER_ENDPOINT *MAP_SIZE_OF_CLUSTER)

// rename map to avoid truncation when name length exceeds BPF_OBJ_NAME_LEN = 16
#define map_of_listener       kmesh_listener
#define map_of_filter_chain   kmesh_filter_chain
#define map_of_filter         kmesh_filter
#define map_of_virtual_host   kmesh_virtual_host
#define map_of_route          kmesh_route
#define map_of_cluster        kmesh_cluster
#define map_of_loadbalance    kmesh_loadbalance
#define map_of_endpoint       kmesh_endpoint
#define map_of_tail_call_prog kmesh_tail_call_prog
#define map_of_tail_call_ctx  kmesh_tail_call_ctx

// ************
// array len
#define KMESH_NAME_LEN               64
#define KMESH_TYPE_LEN               64
#define KMESH_HOST_LEN               128
#define KMESH_FILTER_CHAINS_LEN      64
#define KMESH_HTTP_DOMAIN_NUM        32
#define KMESH_HTTP_DOMAIN_LEN        128
#define KMESH_PER_FILTER_CHAIN_NUM   MAP_SIZE_OF_PER_FILTER_CHAIN
#define KMESH_PER_FILTER_NUM         MAP_SIZE_OF_PER_FILTER
#define KMESH_PER_VIRT_HOST_NUM      MAP_SIZE_OF_PER_VIRTUAL_HOST
#define KMESH_PER_ROUTE_NUM          MAP_SIZE_OF_PER_ROUTE
#define KMESH_PER_ENDPOINT_NUM       MAP_SIZE_OF_PER_ENDPOINT
#define KMESH_PER_HEADER_MUM         32
#define KMESH_PER_WEIGHT_CLUSTER_NUM 32
#endif // _CONFIG_H_
