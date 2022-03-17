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
 * Create: 2022-02-26
 */
#ifndef __ROUTE_CONFIG_H__
#define __ROUTE_CONFIG_H__

#include "kmesh_common.h"
#include "tail_call.h"
#include "route/route.pb-c.h"

#define ROUTER_NAME_MAX_LEN		BPF_DATA_MAX_LEN

bpf_map_t SEC("maps") map_of_router_config = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= ROUTER_NAME_MAX_LEN,
	.value_size		= sizeof(Route__RouteConfiguration),
	.max_entries	= MAP_SIZE_OF_ROUTE,
	.map_flags		= 0,
};

static inline
Route__RouteConfiguration * map_lookup_route_config(const char *route_name)
{
	if (!route_name) {
		return NULL;
	}

	return kmesh_map_lookup_elem(&map_of_router_config, route_name);
}

static inline 
int virtual_host_match_check(Route__VirtualHost *virt_host, address_t *addr, ctx_buff_t *ctx, struct bpf_mem_ptr *msg)
{
	int i;
	void *domains = NULL;
	void *domain = NULL;
	void *ptr;
	size_t n_domains = virt_host->n_domains;

	ptr = _(msg->ptr);
	if (!ptr)
		return 0;

	if (!virt_host->domains)
		return 0;

	domains = kmesh_get_ptr_val(_(virt_host->domains));
	if (!domains)
		return 0;

	n_domains = BPF_MIN(n_domains, KMESH_HTTP_DOMAIN_NUM);
#pragma unroll
	for (i = 0; i < n_domains; i++) {
		domain = kmesh_get_ptr_val((void*)*((__u64*)domains + i));
		if (!domain)
			continue;

		if (bpf_strstr(ptr, domain) != NULL) {
			BPF_LOG(DEBUG, ROUTER_CONFIG, "match virtual_host, name=\"%s\"\n",
				(char *)kmesh_get_ptr_val(virt_host->name));
			return 1;
		}
	}

	return 0;
}

static inline
Route__VirtualHost * virtual_host_match(Route__RouteConfiguration *route_config, 
					address_t *addr, 
					ctx_buff_t *ctx,
					struct bpf_mem_ptr *msg)
{
	int i;
	void *ptrs = NULL;
	size_t n_virt_hosts = _(route_config->n_virtual_hosts);
	Route__VirtualHost *virt_host = NULL;

	if (n_virt_hosts <= 0 || n_virt_hosts > KMESH_PER_VIRT_HOST_NUM) {
		BPF_LOG(WARN, ROUTER_CONFIG, "invalid virt hosts num=%d\n", n_virt_hosts);
		return NULL;
	}

	ptrs = kmesh_get_ptr_val(_(route_config->virtual_hosts));
	if (!ptrs) {
		BPF_LOG(ERR, ROUTER_CONFIG, "failed to get virtual hosts\n");
		return NULL;
	}

	n_virt_hosts = BPF_MIN(n_virt_hosts, KMESH_PER_VIRT_HOST_NUM);
#pragma unroll
	for (i = 0; i < n_virt_hosts; i++) {
		virt_host = kmesh_get_ptr_val((void*)*((__u64*)ptrs + i));
		if (!virt_host) {
			continue;
		}

		if (virtual_host_match_check(virt_host, addr, ctx, msg)) {
			return virt_host;
		}
	}
	return NULL;
}

static inline
int virtual_host_route_match_check(Route__Route *route, address_t *addr, ctx_buff_t *ctx, struct bpf_mem_ptr *msg)
{
	Route__RouteMatch *match;
	char *prefix;
	void *ptr;

	ptr = _(msg->ptr);
	if (!ptr)
		return 0;

	if (!route->match)
		return 0;

	match = kmesh_get_ptr_val(route->match);
	if (!match)
		return 0;

	prefix = kmesh_get_ptr_val(match->prefix);
	if (!prefix)
		return 0;

	if (bpf_strstr(ptr, prefix) == NULL)
		return 0;

	BPF_LOG(DEBUG, ROUTER_CONFIG, "match route, name=\"%s\"\n",
		(char *)kmesh_get_ptr_val(route->name));
	return 1;
}

static inline
Route__Route * virtual_host_route_match(Route__VirtualHost *virt_host, address_t *addr, ctx_buff_t *ctx, struct bpf_mem_ptr *msg)
{
	int i;
	void *ptrs = NULL;
	Route__Route *route = NULL;
	size_t n_routes = _(virt_host->n_routes);

	if (n_routes <= 0 || n_routes > KMESH_PER_ROUTE_NUM) {
		BPF_LOG(WARN, ROUTER_CONFIG, "invalid virtual route num(%d)\n", n_routes);
		return NULL;
	}

	ptrs = kmesh_get_ptr_val(_(virt_host->routes));
	if (!ptrs) {
		BPF_LOG(ERR, ROUTER_CONFIG, "failed to get routes\n");
		return NULL;
	}

	n_routes = BPF_MIN(n_routes, KMESH_PER_ROUTE_NUM);
#pragma unroll
	for (i = 0; i < n_routes; i++) {
		route = (Route__Route *)kmesh_get_ptr_val((void*)*((__u64*)ptrs + i));
		if (!route) {
			continue;
		}

		if (virtual_host_route_match_check(route, addr, ctx, msg)) {
			return route;
		}
	}
	return NULL;
}
#endif
