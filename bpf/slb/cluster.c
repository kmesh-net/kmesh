/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2021-09-17
 */

#include "bpf_log.h"
#include "cluster.h"
#include "endpoint.h"
#include "tail_call.h"
#include "xdp.h"

static inline
int cluster_handle_circuit_breaker(cluster_t *cluster)
{
	// TODO
	return 0;
}

static inline
endpoint_t *loadbalance_round_robin(load_assignment_t *load_assignment)
{
	int ret;
	loadbalance_t *lb = NULL;
	endpoint_t *endpoint = NULL;

	lb = map_lookup_loadbalance(&load_assignment->map_key_of_endpoint);
	if (lb == NULL)
		return NULL;

	endpoint = map_lookup_endpoint(&lb->map_key);
	if (endpoint == NULL) {
		lb->map_key.index = 0;
		endpoint = map_lookup_endpoint(&lb->map_key);
	}

	lb->map_key.index++;
	ret = map_update_loadbalance(&load_assignment->map_key_of_endpoint, lb);
	if (ret != 0)
		BPF_LOG(ERR, KMESH, "map_of_loadbalance update failed\n");

	return endpoint;
}

static inline
endpoint_t *loadbalance_least_request(load_assignment_t *load_assignment)
{
	int ret;
	unsigned i;
	map_key_t map_key, least_map_key;
	loadbalance_t least_lb = {};
	loadbalance_t *lb = NULL;
	endpoint_t *endpoint = NULL;

	map_key = load_assignment->map_key_of_endpoint;
	least_map_key = load_assignment->map_key_of_endpoint;
	least_lb.lb_conn_num = UINT32_MAX;

	for (i = 0; i < MAP_SIZE_OF_PER_ENDPOINT; i++) {
		map_key.index = i;

		lb = map_lookup_loadbalance(&map_key);
		if (lb == NULL)
			break;

		if (lb->lb_conn_num < least_lb.lb_conn_num) {
			least_lb = *lb;
			least_map_key = map_key;
		}
	}

	endpoint = map_lookup_endpoint(&least_map_key);
	if (endpoint != NULL) {
		// TODO: -1 when disconn
		least_lb.lb_conn_num++;
		ret = map_update_loadbalance(&least_map_key, &least_lb);
		if (ret != 0)
			BPF_LOG(ERR, KMESH, "map_of_loadbalance update failed\n");
	}

	return endpoint;
}

static inline
int cluster_handle_loadbalance(ctx_buff_t *ctx,
                               load_assignment_t *load_assignment,
                               address_t* src_address bpf_unused,
                               address_t* origin_dst bpf_unused)
{
	endpoint_t *endpoint = NULL;

	BPF_LOG(DEBUG, KMESH, "cluster.load_assignment, port %u, lb_policy %u\n",
		load_assignment->map_key_of_endpoint.port, load_assignment->lb_policy);

	switch (load_assignment->lb_policy) {
		case LB_POLICY_ROUND_ROBIN:
			endpoint = loadbalance_round_robin(load_assignment);
			break;
		case LB_POLICY_LEAST_REQUEST:
			endpoint = loadbalance_least_request(load_assignment);
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

	BPF_LOG(DEBUG, KMESH, "endpoint.address, ipv4 %u, port %u\n",
		endpoint->address.ipv4, endpoint->address.port);

#ifdef XDP_ACCELERATE_ENABLE
	return xdp_dnat(ctx, src_address, origin_dst, &endpoint->address, true);
#else
	SET_CTX_ADDRESS(ctx, &endpoint->address);
	return 0;
#endif
}

SEC_TAIL(KMESH_SOCKET_CALLS, KMESH_TAIL_CALL_CLUSTER)
int cluster_manager(ctx_buff_t *ctx)
{
	int ret;
	map_key_t *pkey = NULL;
	ctx_key_t ctx_key;
	cluster_t *cluster = NULL;
    address_t src_address = {0};

#ifdef XDP_ACCELERATE_ENABLE
    address_t address = {0};
    parse_xdp_address(ctx, false, &src_address, &address);
#else
    DECLARE_VAR_ADDRESS(ctx, address);
#endif

	ctx_key.address = address;
	ctx_key.tail_call_index = KMESH_TAIL_CALL_CLUSTER;
    BPF_LOG(DEBUG, KMESH, "cluster_manager., ip %u, port %u\n",
            address.ipv4, address.port);
	pkey = kmesh_tail_lookup_ctx(&ctx_key);
	if (pkey == NULL)
		return convert_sock_errno(ENOENT);

	cluster = map_lookup_cluster(pkey);
	kmesh_tail_delete_ctx(&ctx_key);
	if (cluster == NULL) {
        BPF_LOG(DEBUG, KMESH, "cluster_manager.can not find cluster; ip %u, port %u\n",
                address.ipv4, address.port);
        return convert_sock_errno(ENOENT);
    }

	if (cluster_handle_circuit_breaker(cluster) != 0)
		return convert_sock_errno(EBUSY);

	ret = cluster_handle_loadbalance(ctx, &cluster->load_assignment, &src_address, &address);
#ifdef XDP_ACCELERATE_ENABLE
    BPF_LOG(DEBUG, KMESH, "xdp_cluster_manager.ret %u\n", ret);
    return convert_xdp_error(ret);
#endif
	return convert_sock_errno(ret);
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;