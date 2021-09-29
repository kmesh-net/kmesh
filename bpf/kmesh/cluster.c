/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

#include "bpf_log.h"
#include "cluster.h"
#include "endpoint.h"
#include "tail_call.h"

static inline
int cluster_handle_circuit_breaker(cluster_t *cluster)
{
	// TODO
	return 0;
}

static inline
endpoint_t *loadbanance_least_request(load_assignment_t *load_assignment)
{
	map_key_t *map_key = NULL;

	map_key = &load_assignment->map_key_of_least_endpoint;

	map_key->index++;
	map_key->index %= load_assignment->map_key_of_endpoint.index;

	return map_lookup_endpoint(map_key);
}

static inline
endpoint_t *loadbanance_round_robin(load_assignment_t *load_assignment)
{
	unsigned index, i;
	map_key_t map_key;
	endpoint_t *endpoint = NULL;
	
	map_key.nameid = load_assignment->map_key_of_endpoint.nameid;
	index = BPF_MIN(load_assignment->map_key_of_endpoint.index, MAP_SIZE_OF_PER_ENDPOINT);

	for (i = 0; i < index; i++) {
		map_key.index = i;

		endpoint_t *ep = map_lookup_endpoint(&map_key);
		if (ep == NULL)
			return NULL;

		if ((endpoint == NULL) || (endpoint->lb_conn_num > ep->lb_conn_num))
			endpoint = ep;
	}

	// TODO: -1 when disconn
	endpoint->lb_conn_num++;
	return endpoint;
}

static inline
int cluster_handle_loadbanance(ctx_buff_t *ctx, load_assignment_t *load_assignment)
{
	endpoint_t *endpoint = NULL;

	switch (load_assignment->lb_policy) {
		case LB_POLICY_LEAST_REQUEST:
			endpoint = loadbanance_least_request(load_assignment);
			break;
		case LB_POLICY_ROUND_ROBIN:
			endpoint = loadbanance_round_robin(load_assignment);
			break;
		case LB_POLICY_RANDOM:
			// TODO
			break;
		default:
			BPF_LOG(ERR, KMESH, "load_assignment lb_policy is wrong\n");
			break;
	}

	if (endpoint == NULL)
		return -EAGAIN;
	SET_CTX_ADDRESS(ctx, &endpoint->address);

	return 0;
}

SEC_TAIL(socket, KMESH_TAIL_CALL_CLUSTER)
int cluster_manager(ctx_buff_t *ctx)
{
	cluster_t *cluster = NULL;

	DECLARE_VAR_ADDRESS(ctx, address);

	cluster = kmesh_tail_lookup_ctx(&address);
	if (cluster == NULL) {
		return -ENOENT;
	}
	kmesh_tail_delete_ctx(&address);

	if (cluster_handle_circuit_breaker(cluster) != 0)
		return -EBUSY;

	return cluster_handle_loadbanance(ctx, &cluster->load_assignment);
}

