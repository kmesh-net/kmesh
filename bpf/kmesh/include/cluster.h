/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, CLUSTER_NAME_MAX_LEN);
	__uint(value_size, sizeof(Cluster__Cluster));
	__uint(map_flags, 0);
	__uint(max_entries, MAP_SIZE_OF_CLUSTER);
} map_of_cluster SEC(".maps");

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, CLUSTER_NAME_MAX_LEN);
	__uint(value_size, sizeof(struct cluster_endpoints));
	__uint(max_entries, MAP_SIZE_OF_ENDPOINT);
	__uint(map_flags, 0);
} map_of_cluster_eps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct cluster_endpoints));
	__uint(max_entries, 1);
} map_of_cluster_eps_data SEC(".maps");

static inline Cluster__Cluster *map_lookup_cluster_eps_data()
{
	int location = 0;
	return kmesh_map_lookup_elem(&map_of_cluster_eps_data, &location);
}

static inline Cluster__Cluster *map_lookup_cluster(const char *cluster_name)
{
	return kmesh_map_lookup_elem(&map_of_cluster, cluster_name);
}

static inline struct cluster_endpoints *map_lookup_cluster_eps(const char *cluster_name)
{
	return kmesh_map_lookup_elem(&map_of_cluster_eps, cluster_name);
}

static inline int map_add_cluster_eps(const char *cluster_name, const struct cluster_endpoints *eps)
{
	return kmesh_map_update_elem(&map_of_cluster_eps, cluster_name, eps);
}

static inline int cluster_add_endpoints(const Endpoint__LocalityLbEndpoints *lb_ep,
										struct cluster_endpoints *cluster_eps)
{
	__u32 i;
	void *ep_ptrs = NULL;

	ep_ptrs = kmesh_get_ptr_val(lb_ep->lb_endpoints);
	if (!ep_ptrs)
		return -1;

	for (i = 0; i < KMESH_PER_ENDPOINT_NUM; i++) {
		if (i >= lb_ep->n_lb_endpoints || cluster_eps->ep_num >= KMESH_PER_ENDPOINT_NUM)
			break;

		/* store ep identity */
		cluster_eps->ep_identity[cluster_eps->ep_num++] = (__u64)*((__u64*)ep_ptrs + i);
	}
	return 0;
}

static inline __u32 cluster_get_endpoints_num(const Endpoint__ClusterLoadAssignment *cla)
{
	__u32 i;
	__u32 num = 0;
	void *ptrs = NULL;
	Endpoint__LocalityLbEndpoints *lb_ep = NULL;

	ptrs = kmesh_get_ptr_val(cla->endpoints);
	if (!ptrs)
		return 0;

	for (i = 0; i < KMESH_PER_ENDPOINT_NUM; i++) {
		if (i >= cla->n_endpoints) {
			break;
		}

		lb_ep = (Endpoint__LocalityLbEndpoints *)kmesh_get_ptr_val((void*)*((__u64*)ptrs + i));
		if (!lb_ep)
			continue;

		num += (__u32)lb_ep->n_lb_endpoints;
	}
	return num;
}

static inline int cluster_init_endpoints(const char *cluster_name,
						const Endpoint__ClusterLoadAssignment *cla)
{
	__u32 i;
	int ret = 0;
	void *ptrs = NULL;
	Endpoint__LocalityLbEndpoints *ep = NULL;
	/* A percpu array map is added to store cluster eps data.
	 * The reason for using percpu array map is that a alarge value exceeds
	 * the 512 bytes limit of the stack in ebpf.
	 */
	struct cluster_endpoints *cluster_eps = map_lookup_cluster_eps_data();

	if (!cluster_eps) {
		BPF_LOG(ERR, CLUSTER, "failed to get percpu cluster eps data\n");
		return -1;
	}
	cluster_eps->ep_num = 0;

	ptrs = kmesh_get_ptr_val(cla->endpoints);
	if (!ptrs) {
		BPF_LOG(ERR, CLUSTER, "failed to get cla endpoints ptrs\n");
		return -1;
	}

	for (i = 0; i < KMESH_PER_ENDPOINT_NUM; i++) {
		if (i >= cla->n_endpoints)
			break;

		ep = (Endpoint__LocalityLbEndpoints *)kmesh_get_ptr_val((void*)*((__u64*)ptrs + i));
		if (!ep)
			continue;

		ret = cluster_add_endpoints(ep, cluster_eps);
		if (ret != 0)
			return -1;
	}

	return map_add_cluster_eps(cluster_name, cluster_eps);
}

static inline int cluster_check_endpoints(const struct cluster_endpoints *eps,
										const Endpoint__ClusterLoadAssignment *cla)
{
	/* 0 -- failed 1 -- succeed */
	__u32 i;
	void *ptrs = NULL;
	__u32 lb_num = cluster_get_endpoints_num(cla);

	if (!eps || eps->ep_num != lb_num)
		return 0;

	ptrs = kmesh_get_ptr_val(cla->endpoints);
	if (!ptrs)
		return 0;

	for (i = 0; i < KMESH_PER_ENDPOINT_NUM; i++) {
		if (i >= lb_num) {
			break;
		}

		if (eps->ep_identity[i] != (__u64)_(ptrs + i))
			return 0;
	}
	return 1;
}

static inline struct cluster_endpoints *cluster_refresh_endpoints(const Cluster__Cluster *cluster, const char *name)
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
