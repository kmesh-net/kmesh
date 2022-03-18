/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *	 http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: nlgwcy
 * Create: 2022-02-14
 */

#ifndef __KMESH_CLUSTER_H__
#define __KMESH_CLUSTER_H__

#include "kmesh_common.h"
#include "tail_call.h"
#include "cluster/cluster.pb-c.h"
#include "endpoint/endpoint.pb-c.h"

#define CLUSTER_NAME_MAX_LEN	BPF_DATA_MAX_LEN

bpf_map_t SEC("maps") map_of_cluster = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= CLUSTER_NAME_MAX_LEN,
	.value_size		= sizeof(Cluster__Cluster),
	.max_entries	= MAP_SIZE_OF_CLUSTER,
	.map_flags		= 0,
};

struct cluster_endpoints {
	__u32 ep_num;
	/*  */
	__u64 ep_identity[KMESH_PER_ENDPOINT_NUM];
	union {
		/* ROUND_ROBIN */
		__u32 last_round_robin_idx;
		/* LEAST_REQUEST */
		__u32 conn_num[KMESH_PER_ENDPOINT_NUM];
	};
};

bpf_map_t SEC("maps") map_of_cluster_eps = {
	.type			 = BPF_MAP_TYPE_HASH,
	.key_size		= CLUSTER_NAME_MAX_LEN,
	.value_size		= sizeof(struct cluster_endpoints),
	.max_entries	= MAP_SIZE_OF_ENDPOINT,
	.map_flags		 = 0,
};

static inline
Cluster__Cluster * map_lookup_cluster(const char *cluster_name)
{
	return kmesh_map_lookup_elem(&map_of_cluster, cluster_name);
}

static inline 
struct cluster_endpoints * map_lookup_cluster_eps(const char *cluster_name)
{
	return kmesh_map_lookup_elem(&map_of_cluster_eps, cluster_name);
}

static inline
int map_add_cluster_eps(const char *cluster_name, const struct cluster_endpoints *eps)
{
	return kmesh_map_update_elem(&map_of_cluster_eps, cluster_name, eps);
}

static inline
void cluster_set_ep_identity(__u32 idx, __u64 identity, __u64 *ep_identity)
{
	// TODO
	if (idx >= KMESH_PER_ENDPOINT_NUM)
		return;

	if (idx == 0)
		*(ep_identity + 0) = identity;
	if (idx == 1)
		*(ep_identity + 1) = identity;
	if (idx == 2)
		*(ep_identity + 2) = identity;
	if (idx == 3)
		*(ep_identity + 3) = identity;
}

static inline
int cluster_add_endpoints(const Endpoint__LocalityLbEndpoints *lb_ep, struct cluster_endpoints *cluster_eps)
{
	__u32 i;
	void *ep_ptrs = NULL;

	ep_ptrs = kmesh_get_ptr_val(lb_ep->lb_endpoints);
	if (!ep_ptrs) {
		return -1;
	}

#pragma unroll
	for (i = 0; i < KMESH_PER_ENDPOINT_NUM; i++) {
		if (i >= lb_ep->n_lb_endpoints || cluster_eps->ep_num >=  KMESH_PER_ENDPOINT_NUM) {
			break;
		}

		/* store ep identify */
		cluster_set_ep_identity(cluster_eps->ep_num, (__u64)*((__u64*)ep_ptrs + i), cluster_eps->ep_identity);
		cluster_eps->ep_num++;
	}
	return 0;
}

static inline
__u32 cluster_get_endpoints_num(const Endpoint__ClusterLoadAssignment *cla)
{
	__u32 i;
	__u32 num = 0;
	void *ptrs = NULL;
	Endpoint__LocalityLbEndpoints *lb_ep = NULL;
	size_t n_endpoints = cla->n_endpoints;

	ptrs = kmesh_get_ptr_val(cla->endpoints);
	if (!ptrs)
		return -1;

	if (n_endpoints == 0 || n_endpoints > KMESH_PER_ENDPOINT_NUM) {
		BPF_LOG(ERR, CLUSTER, "n_endpoints num(%d) invalid\n", n_endpoints);
		return -1;
	}
	n_endpoints = BPF_MIN(cla->n_endpoints, KMESH_PER_ENDPOINT_NUM);

#pragma unroll
	for (i = 0; i < n_endpoints; i++) {
		lb_ep = (Endpoint__LocalityLbEndpoints *)kmesh_get_ptr_val((void*)*((__u64*)ptrs + i));
		if (!lb_ep) {
			continue;
		}

		num += lb_ep->n_lb_endpoints;
	}
	return num;
}

static inline
int cluster_init_endpoints(const char *cluster_name,  
						const Endpoint__ClusterLoadAssignment *cla)
{
	__u32 i;
	int ret = 0;
	void *ptrs = NULL;
	Endpoint__LocalityLbEndpoints *ep = NULL;
	struct cluster_endpoints cluster_eps = {0};

	ptrs = kmesh_get_ptr_val(cla->endpoints);
	if (!ptrs) {
		BPF_LOG(ERR, CLUSTER, "failed to get cla endpoints ptrs\n");
		return -1;
	}

#pragma unroll
	for (i = 0; i < KMESH_PER_ENDPOINT_NUM; i++) {
		if (i >= cla->n_endpoints) {
			break;
		}

		ep = (Endpoint__LocalityLbEndpoints *)kmesh_get_ptr_val((void*)*((__u64*)ptrs + i));
		if (!ep) {
			continue;
		}

		ret = cluster_add_endpoints(ep, &cluster_eps);
		if (ret != 0) {
			return -1;
		}
	}

	return map_add_cluster_eps(cluster_name, &cluster_eps);
}

static inline
int cluster_check_endpoints(const struct cluster_endpoints *eps, const Endpoint__ClusterLoadAssignment *cla)
{
	/* 0 -- failed 1 -- succeed */
	int i;
	void *ptrs = NULL;
	__u32 lb_num = cluster_get_endpoints_num(cla);

	if (!eps || eps->ep_num != lb_num) {
		return 0;
	}

	ptrs = kmesh_get_ptr_val(cla->endpoints);
	if (!ptrs)
		return 0;

	lb_num = BPF_MIN(lb_num, KMESH_PER_ENDPOINT_NUM);
#pragma unroll
	for (i = 0; i < lb_num; i++) {
		if (eps->ep_identity[i] != (__u64)_(ptrs + i)) {
			return 0;
		}
	}
	return 1;
}

static inline
struct cluster_endpoints *cluster_refresh_endpoints(const Cluster__Cluster *cluster, const char *name)
{
	struct cluster_endpoints *eps = NULL;
	Endpoint__ClusterLoadAssignment *cla = NULL;

	cla = kmesh_get_ptr_val(cluster->load_assignment);
	if (!cla) {
		BPF_LOG(ERR, CLUSTER, "get load_assignment failed\n");
		return NULL;
	}

	// FIXME: if control-plane delete or update, clear
	// FIXME: if cluster_init_endpoints failed, clear
	// FIXME: if cluster_check_endpoints failed, clear
	eps = map_lookup_cluster_eps(name);
	if (eps) // TODO: && cluster_check_endpoints(eps, cla) != 0)
		return eps;

	if (cluster_init_endpoints(name, cla) != 0)
		return NULL;
	return map_lookup_cluster_eps(name);
}
#endif
