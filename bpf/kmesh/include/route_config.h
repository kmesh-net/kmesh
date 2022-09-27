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

static inline Route__RouteConfiguration *map_lookup_route_config(const char *route_name)
{
	if (!route_name)
		return NULL;

	return kmesh_map_lookup_elem(&map_of_router_config, route_name);
}

static inline int virtual_host_match_check(Route__VirtualHost *virt_host,
											address_t *addr, ctx_buff_t *ctx, struct bpf_mem_ptr *msg)
{
	int i;
	void *domains = NULL;
	void *domain = NULL;
	void *ptr;

	ptr = _(msg->ptr);
	if (!ptr)
		return 0;

	if (!virt_host->domains)
		return 0;

	domains = kmesh_get_ptr_val(_(virt_host->domains));
	if (!domains)
		return 0;

	for (i = 0; i < KMESH_HTTP_DOMAIN_NUM; i++) {
		if (i >= virt_host->n_domains) {
			break;
		}

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

static inline Route__VirtualHost *virtual_host_match(Route__RouteConfiguration *route_config,
					address_t *addr,
					ctx_buff_t *ctx,
					struct bpf_mem_ptr *msg)
{
	int i;
	void *ptrs = NULL;
	Route__VirtualHost *virt_host = NULL;

	if (route_config->n_virtual_hosts <= 0 || route_config->n_virtual_hosts > KMESH_PER_VIRT_HOST_NUM) {
		BPF_LOG(WARN, ROUTER_CONFIG, "invalid virt hosts num=%d\n", route_config->n_virtual_hosts);
		return NULL;
	}

	ptrs = kmesh_get_ptr_val(_(route_config->virtual_hosts));
	if (!ptrs) {
		BPF_LOG(ERR, ROUTER_CONFIG, "failed to get virtual hosts\n");
		return NULL;
	}

	for (i = 0; i < KMESH_PER_VIRT_HOST_NUM; i++) {
		if (i >= route_config->n_virtual_hosts) {
			break;
		}

		virt_host = kmesh_get_ptr_val((void*)*((__u64*)ptrs + i));
		if (!virt_host)
			continue;

		if (virtual_host_match_check(virt_host, addr, ctx, msg))
			return virt_host;
	}
	return NULL;
}

static inline char *get_msg_header(char *name) {
	//todo:return head value parse from msg
	return name;
}
static inline bool check_header_value_match(char *target, struct bpf_mem_ptr* head, bool exact) {
	BPF_LOG(DEBUG, ROUTER_CONFIG, "header match, is exact:%d value:%s\n", exact,target);
	if (exact) {
		return (bpf_strncmp(target, _(head->ptr), _(head->size)) == 0);
	} else {
		return (bpf_strnstr(target, _(head->ptr), _(head->size)) != NULL);
	}
}

static inline bool check_headers_match(Route__RouteMatch *match) {
	int i;
	void *ptrs = NULL;
	char *header_name = NULL;
	char *config_header_value = NULL;
	struct bpf_mem_ptr *msg_header= NULL;
	Route__HeaderMatcher *header_match = NULL;

	if (match->n_headers <= 0)
		return true;
	if (match->n_headers > KMESH_PER_HEADER_MUM) {
		BPF_LOG(ERR, ROUTER_CONFIG, "un support header num(%d), no need to check\n", match->n_headers);
		return false;
	}
	ptrs = kmesh_get_ptr_val(_(match->headers));
	if (!ptrs) {
		BPF_LOG(ERR, ROUTER_CONFIG, "failed to get match headers in route match\n");
		return false;
	}
	for (i = 0; i < KMESH_PER_HEADER_MUM; i++) {
		if (i >= match->n_headers) {
			break;
		}
		header_match = (Route__HeaderMatcher *) kmesh_get_ptr_val((void *)*((__u64*)ptrs + i));
		if (!header_match) {
			BPF_LOG(ERR, ROUTER_CONFIG, "failed to get match headers in route match\n");
			return false;
		}
		header_name = kmesh_get_ptr_val(header_match->name);
		if (!header_name) {
			BPF_LOG(ERR, ROUTER_CONFIG, "failed to get match headers in route match\n");
			return false;
		}
		msg_header = (struct bpf_mem_ptr *) bpf_get_protocol_element(header_name);
		if (!msg_header) {
			BPF_LOG(ERR, ROUTER_CONFIG, "failed to get header value form msg\n");
			return false;
		}
		BPF_LOG(DEBUG, ROUTER_CONFIG, "header match check, name:%s\n", header_name);
		switch (header_match->header_match_specifier_case) {
			case ROUTE__HEADER_MATCHER__HEADER_MATCH_SPECIFIER_EXACT_MATCH: {
				config_header_value = kmesh_get_ptr_val(header_match->exact_match);
				if (config_header_value == NULL) {
					BPF_LOG(ERR, ROUTER_CONFIG, "failed to get config_header_value\n");
				}
				if (!check_header_value_match(config_header_value, msg_header, true)) {
					return false;
				}
				break;
			}
			case ROUTE__HEADER_MATCHER__HEADER_MATCH_SPECIFIER_PREFIX_MATCH: {
				config_header_value = kmesh_get_ptr_val(header_match->prefix_match);
				if (config_header_value == NULL) {
					BPF_LOG(ERR, ROUTER_CONFIG, "prefix:failed to get config_header_value\n");
				}
				if (!check_header_value_match(config_header_value, msg_header, false)) {
					return false;
				}
				break;
			}
			default:
				BPF_LOG(ERR, ROUTER_CONFIG, "un-support match type:%d\n", header_match->header_match_specifier_case);
				return false;
		}
	}
	return true;
}

static inline int virtual_host_route_match_check(Route__Route *route,
												address_t *addr, ctx_buff_t *ctx, struct bpf_mem_ptr *msg)
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

	if (!check_headers_match(match))
		return 0;

	BPF_LOG(DEBUG, ROUTER_CONFIG, "match route, name=\"%s\"\n",
		(char *)kmesh_get_ptr_val(route->name));
	return 1;
}

static inline Route__Route *virtual_host_route_match(Route__VirtualHost *virt_host,
													address_t *addr, ctx_buff_t *ctx, struct bpf_mem_ptr *msg)
{
	int i;
	void *ptrs = NULL;
	Route__Route *route = NULL;

	if (virt_host->n_routes <= 0 || virt_host->n_routes > KMESH_PER_ROUTE_NUM) {
		BPF_LOG(WARN, ROUTER_CONFIG, "invalid virtual route num(%d)\n", virt_host->n_routes);
		return NULL;
	}

	ptrs = kmesh_get_ptr_val(_(virt_host->routes));
	if (!ptrs) {
		BPF_LOG(ERR, ROUTER_CONFIG, "failed to get routes ptrs\n");
		return NULL;
	}

	for (i = 0; i < KMESH_PER_ROUTE_NUM; i++) {
		if (i >= virt_host->n_routes) {
			break;
		}

		route = (Route__Route *)kmesh_get_ptr_val((void*)*((__u64*)ptrs + i));
		if (!route)
			continue;

		if (virtual_host_route_match_check(route, addr, ctx, msg))
			return route;
	}
	return NULL;
}
#endif
