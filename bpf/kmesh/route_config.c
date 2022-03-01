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
 * Create: 2022-02-15
 */

#include "bpf_log.h"
#include "route_config.h"
#include "tail_call.h"

static inline
char * route_get_cluster(const Route__Route *route)
{
	Route__RouteAction *route_act = NULL;

	route_act = kmesh_get_ptr_val(_(route->route));
	if (!route_act) {
		BPF_LOG(ERR, ROUTER_CONFIG, "failed to get route action ptr\n");
		return NULL;
	}

	return kmesh_get_ptr_val(_(route_act->cluster));
}

SEC_TAIL(KMESH_SOCKOPS_CALLS, KMESH_TAIL_CALL_ROUTER_CONFIG)
int route_config_manager(ctx_buff_t *ctx)
{
	int ret;
	char *cluster = NULL;
	ctx_key_t ctx_key = {0};
	ctx_val_t *ctx_val = NULL;
	ctx_val_t ctx_val_1 = {0};
	Route__RouteConfiguration *route_config = NULL;
	Route__VirtualHost *virt_host = NULL;
	Route__Route *route = NULL;

	DECLARE_VAR_ADDRESS(ctx, addr);
	ctx_key.address = addr;
	ctx_key.tail_call_index = KMESH_TAIL_CALL_ROUTER_CONFIG;
	ctx_val = kmesh_tail_lookup_ctx(&ctx_key);
	if (!ctx_val) {
		return convert_sockops_ret(-1);
	}

	route_config = map_lookup_route_config(ctx_val->data);
	kmesh_tail_delete_ctx(&ctx_key);
	if (!route_config) {
		BPF_LOG(ERR, ROUTER_CONFIG, "failed to get route config\n");
		return convert_sockops_ret(-1);
	}

	virt_host = virtual_host_match(route_config, &addr, ctx);
	if (!virt_host) {
		BPF_LOG(ERR, ROUTER_CONFIG, "failed to get virtual host\n");
		return convert_sockops_ret(-1);
	}

	route = virtual_host_route_match(virt_host, &addr, ctx);
	if (!route) {
		BPF_LOG(ERR, ROUTER_CONFIG, "failed to get route action\n");
		return convert_sockops_ret(-1);
	}

	cluster = route_get_cluster(route);
	if (!cluster) {
		BPF_LOG(ERR, ROUTER_CONFIG, "failed to get cluster\n");
		return convert_sockops_ret(-1);
	}

	ctx_key.address = addr;
	ctx_key.tail_call_index = KMESH_TAIL_CALL_CLUSTER;
	ret = bpf_strcpy(ctx_val_1.data, BPF_DATA_MAX_LEN, cluster);
	if (ret != 0) {
		BPF_LOG(ERR, ROUTER_CONFIG, "failed to copy cluster %s\n", cluster);
		return convert_sockops_ret(-1);
	}

	ret = kmesh_tail_update_ctx(&ctx_key, &ctx_val_1);
	if (ret != 0) {
		return convert_sockops_ret(ret);
	}

	kmesh_tail_call(ctx, KMESH_TAIL_CALL_CLUSTER);
	kmesh_tail_delete_ctx(&ctx_key);
	return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
