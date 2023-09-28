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

#include "bpf_log.h"
#include "cluster.h"
#include "cluster/cluster.pb-c.h"
#include "tail_call.h"

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

	BPF_LOG(DEBUG, CLUSTER, "cluster=\"%s\", loadbalance to addr=[%u:%u]\n",
			name, sock_addr->ipv4, sock_addr->port);
	SET_CTX_ADDRESS(ctx, sock_addr);
	return 0;
}

SEC_TAIL(KMESH_SOCKOPS_CALLS, KMESH_TAIL_CALL_CLUSTER)
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

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
