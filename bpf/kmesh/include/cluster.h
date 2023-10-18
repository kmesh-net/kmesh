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
 * Create: 2022-02-14
 */

#ifndef __KMESH_CLUSTER_H__
#define __KMESH_CLUSTER_H__

#include "bpf_log.h"
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

static inline void *loadbalance_round_robin(struct cluster_endpoints *eps)
{
	if (!eps || eps->ep_num == 0)
		return NULL;

	__u32 idx = eps->last_round_robin_idx % eps->ep_num;
	if (idx >= KMESH_PER_ENDPOINT_NUM)
		return NULL;

	__sync_fetch_and_add(&eps->last_round_robin_idx, 1);
	return (void *)eps->ep_identity[idx];
}

static inline void *cluster_get_ep_identity_by_lb_policy(struct cluster_endpoints *eps, __u32 lb_policy)
{
	void *ep_identity = NULL;

	switch (lb_policy) {
		case CLUSTER__CLUSTER__LB_POLICY__ROUND_ROBIN:
			ep_identity = loadbalance_round_robin(eps);
			break;
		default:
			BPF_LOG(INFO, CLUSTER, "%d lb_policy is unsupport, defaut:ROUND_ROBIN\n", lb_policy);
			ep_identity = loadbalance_round_robin(eps);
			break;
	}
	return ep_identity;
}

static inline Core__SocketAddress *cluster_get_ep_sock_addr(const void *ep_identity)
{
	Endpoint__Endpoint *ep = NULL;
	Core__SocketAddress *sock_addr = NULL;

	ep = kmesh_get_ptr_val(ep_identity);
	if (!ep) {
		BPF_LOG(ERR, CLUSTER, "cluster get ep failed\n");
		return NULL;
	}

	sock_addr = kmesh_get_ptr_val(ep->address);
	if (!sock_addr) {
		BPF_LOG(ERR, CLUSTER, "ep get sock addr failed\n");
		return NULL;
	}
	return sock_addr;
}

static inline int cluster_handle_loadbalance(Cluster__Cluster *cluster, address_t *addr, ctx_buff_t *ctx)
{
	char *name = NULL;
	void *ep_identity = NULL;
	Core__SocketAddress *sock_addr = NULL;
	struct cluster_endpoints *eps = NULL;

	name = kmesh_get_ptr_val(cluster->name);
	if (!name) {
		BPF_LOG(ERR, CLUSTER, "filed to get cluster\n");
		return -EAGAIN;
	}

	eps = cluster_refresh_endpoints(cluster, name);
	if (!eps) {
		BPF_LOG(ERR, CLUSTER, "failed to reflush cluster(%s) endpoints\n", name);
		return -EAGAIN;
	}

	ep_identity = cluster_get_ep_identity_by_lb_policy(eps, cluster->lb_policy);
	if (!ep_identity) {
		BPF_LOG(ERR, CLUSTER, "cluster=\"%s\" handle lb failed, %u\n", name);
		return -EAGAIN;
	}

	sock_addr = cluster_get_ep_sock_addr(ep_identity);
	if (!sock_addr) {
		BPF_LOG(ERR, CLUSTER, "ep get sock addr failed, %ld\n", (__s64)ep_identity);
		return -EAGAIN;
	}

	BPF_LOG(INFO, CLUSTER, "cluster=\"%s\", loadbalance to addr=[%u:%u]\n",
			name, sock_addr->ipv4, sock_addr->port);
	SET_CTX_ADDRESS(ctx, sock_addr);
	return 0;
}

SEC_TAIL(KMESH_PORG_CALLS, KMESH_TAIL_CALL_CLUSTER)
int cluster_manager(ctx_buff_t *ctx)
{
	int ret = 0;
	ctx_key_t ctx_key = {0};
	ctx_val_t *ctx_val = NULL;
	Cluster__Cluster *cluster = NULL;

	DECLARE_VAR_ADDRESS(ctx, addr);

	ctx_key.address = addr;
	ctx_key.tail_call_index = KMESH_TAIL_CALL_CLUSTER + bpf_get_current_task();

	ctx_val = kmesh_tail_lookup_ctx(&ctx_key);
	if (ctx_val == NULL)
		return convert_sock_errno(ENOENT);

	cluster = map_lookup_cluster(ctx_val->data);
	kmesh_tail_delete_ctx(&ctx_key);
	if (cluster == NULL)
		return convert_sock_errno(ENOENT);

	ret = cluster_handle_loadbalance(cluster, &addr, ctx);
	return convert_sock_errno(ret);
}

#endif
