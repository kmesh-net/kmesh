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

 * Author: supercharge
 * Create: 2023-06-15
 */

#ifndef __TCP_PROXY_H__
#define __TCP_PROXY_H__

#include "filter/tcp_proxy.pb-c.h"
#include "kmesh_common.h"
#include "tail_call.h"

static inline char *select_tcp_weight_cluster(const Filter__TcpProxy *tcpProxy)
{
	void *clusters = NULL;
	Filter__TcpProxy__WeightedCluster *weightedClusters = NULL;
	Filter__TcpProxy__WeightedCluster__ClusterWeight *cluster_weight = NULL;
	int32_t select_value;
	void *cluster_name = NULL;

	weightedClusters = (Filter__TcpProxy__WeightedCluster *)kmesh_get_ptr_val((tcpProxy->weighted_clusters));
	if (!weightedClusters) {
		return NULL;
	}
	clusters = kmesh_get_ptr_val(weightedClusters->clusters);
	if (!clusters) {
		return NULL;
	}

	select_value = (int)(bpf_get_prandom_u32() % 100);
	for (int i = 0; i < KMESH_PER_WEIGHT_CLUSTER_NUM; i ++) {
		if (i >= weightedClusters->n_clusters) {
			break;
		}
		cluster_weight = (Filter__TcpProxy__WeightedCluster__ClusterWeight *) kmesh_get_ptr_val(
						(void *) *((__u64 *) clusters + i));
		if (!cluster_weight) {
			return NULL;
		}
		select_value = select_value - (int)cluster_weight->weight;
		if (select_value <= 0) {
			cluster_name = kmesh_get_ptr_val(cluster_weight->name);
			BPF_LOG(DEBUG, FILTER, "select cluster, %s:%d\n", cluster_name, cluster_weight->weight);
			return (char*)cluster_name;
		}
	}
	return NULL;
}


static inline char *tcp_proxy_get_cluster(const Filter__TcpProxy *tcpProxy)
{
	if (tcpProxy->cluster_specifier_case == FILTER__TCP_PROXY__CLUSTER_SPECIFIER_WEIGHTED_CLUSTERS) {
		return select_tcp_weight_cluster(tcpProxy);
	}

	return (char*)kmesh_get_ptr_val(tcpProxy->cluster);
}

static inline int tcp_proxy_manager(const Filter__TcpProxy *tcpProxy, ctx_buff_t *ctx)
{
	int ret;
	char *cluster = NULL;
	DECLARE_VAR_ADDRESS(ctx, addr);
	ctx_key_t ctx_key = {0};
	ctx_val_t ctx_val = {0};

	if (NULL == tcpProxy)
		return convert_sock_errno(-EINVAL);
	cluster = tcp_proxy_get_cluster(tcpProxy);
	ctx_key.address = addr;
	ctx_key.tail_call_index = KMESH_TAIL_CALL_CLUSTER + bpf_get_current_task();
	if (!bpf_strncpy(ctx_val.data, BPF_DATA_MAX_LEN, cluster)) {
		BPF_LOG(ERR, FILTER, "failed to copy cluster %s\n", cluster);
		return convert_sock_errno(ret);
	}

	ret = kmesh_tail_update_ctx(&ctx_key, &ctx_val);
	if (ret != 0)
		return convert_sock_errno(ret);
	BPF_LOG(DEBUG, FILTER, "tcp_proxy_manager cluster %s\n", cluster);
	kmesh_tail_call(ctx, KMESH_TAIL_CALL_CLUSTER);
	kmesh_tail_delete_ctx(&ctx_key);
	return 0;
}

#endif // __TCP_PROXY_H__
