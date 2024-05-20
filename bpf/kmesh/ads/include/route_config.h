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
 * Create: 2022-02-26
 */
#ifndef __ROUTE_CONFIG_H__
#define __ROUTE_CONFIG_H__

#include "bpf_log.h"
#include "kmesh_common.h"
#include "tail_call.h"
#include "route/route.pb-c.h"

#define ROUTER_NAME_MAX_LEN BPF_DATA_MAX_LEN

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, ROUTER_NAME_MAX_LEN);
    __uint(value_size, sizeof(Route__RouteConfiguration));
    __uint(max_entries, MAP_SIZE_OF_ROUTE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_of_router_config SEC(".maps");

static inline Route__RouteConfiguration *map_lookup_route_config(const char *route_name)
{
    if (!route_name)
        return NULL;

    return kmesh_map_lookup_elem(&map_of_router_config, route_name);
}

static inline int
virtual_host_match_check(Route__VirtualHost *virt_host, address_t *addr, ctx_buff_t *ctx, struct bpf_mem_ptr *host)
{
    int i;
    void *domains = NULL;
    void *domain = NULL;
    void *ptr;
    __u32 ptr_length;

    if (!host)
        return 0;

    ptr = _(host->ptr);
    if (!ptr)
        return 0;

    ptr_length = _(host->size);

    if (!virt_host->domains)
        return 0;

    domains = kmesh_get_ptr_val(_(virt_host->domains));
    if (!domains)
        return 0;

    for (i = 0; i < KMESH_HTTP_DOMAIN_NUM; i++) {
        if (i >= virt_host->n_domains) {
            break;
        }

        domain = kmesh_get_ptr_val((void *)*((__u64 *)domains + i));
        if (!domain)
            continue;

        if (((char *)domain)[0] == '*' && ((char *)domain)[1] == '\0')
            return 1;

        if (bpf_strnstr(ptr, domain, ptr_length) != NULL) {
            BPF_LOG(
                DEBUG, ROUTER_CONFIG, "match virtual_host, name=\"%s\"\n", (char *)kmesh_get_ptr_val(virt_host->name));
            return 1;
        }
    }

    return 0;
}

static inline bool VirtualHost_check_allow_any(char *name)
{
    char allow_any[10] = {'a', 'l', 'l', 'o', 'w', '_', 'a', 'n', 'y', '\0'};
    if (name && bpf__strncmp(allow_any, 10, name) == 0) {
        return true;
    }
    return false;
}

static inline Route__VirtualHost *
virtual_host_match(Route__RouteConfiguration *route_config, address_t *addr, ctx_buff_t *ctx)
{
    int i;
    void *ptrs = NULL;
    Route__VirtualHost *virt_host = NULL;
    Route__VirtualHost *virt_host_allow_any = NULL;
    char host_key[5] = {'H', 'o', 's', 't', '\0'};
    struct bpf_mem_ptr *host;

    if (route_config->n_virtual_hosts <= 0 || route_config->n_virtual_hosts > KMESH_PER_VIRT_HOST_NUM) {
        BPF_LOG(WARN, ROUTER_CONFIG, "invalid virt hosts num=%d\n", route_config->n_virtual_hosts);
        return NULL;
    }

    ptrs = kmesh_get_ptr_val(_(route_config->virtual_hosts));
    if (!ptrs) {
        BPF_LOG(ERR, ROUTER_CONFIG, "failed to get virtual hosts\n");
        return NULL;
    }

    host = bpf_get_msg_header_element(host_key);
    if (!host) {
        BPF_LOG(ERR, ROUTER_CONFIG, "failed to get URI in msg\n");
        return NULL;
    }

    for (i = 0; i < KMESH_PER_VIRT_HOST_NUM; i++) {
        if (i >= route_config->n_virtual_hosts) {
            break;
        }

        virt_host = kmesh_get_ptr_val((void *)*((__u64 *)ptrs + i));
        if (!virt_host)
            continue;

        if (VirtualHost_check_allow_any((char *)kmesh_get_ptr_val(virt_host->name))) {
            virt_host_allow_any = virt_host;
            continue;
        }

        if (virtual_host_match_check(virt_host, addr, ctx, host))
            return virt_host;
    }
    // allow_any as the default virt_host
    if (virt_host_allow_any && virtual_host_match_check(virt_host_allow_any, addr, ctx, host))
        return virt_host_allow_any;
    return NULL;
}

static inline bool check_header_value_match(char *target, struct bpf_mem_ptr *head, bool exact)
{
    BPF_LOG(DEBUG, ROUTER_CONFIG, "header match, is exact:%d value:%s\n", exact, target);
    long target_length = bpf_strnlen(target, BPF_DATA_MAX_LEN);
    if (!exact)
        return (bpf__strncmp(target, target_length, _(head->ptr)) == 0);
    if (target_length != _(head->size))
        return false;
    return (bpf__strncmp(target, target_length, _(head->ptr)) == 0);
}

static inline bool check_headers_match(Route__RouteMatch *match)
{
    int i;
    void *ptrs = NULL;
    char *header_name = NULL;
    char *config_header_value = NULL;
    struct bpf_mem_ptr *msg_header = NULL;
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
        header_match = (Route__HeaderMatcher *)kmesh_get_ptr_val((void *)*((__u64 *)ptrs + i));
        if (!header_match) {
            BPF_LOG(ERR, ROUTER_CONFIG, "failed to get match headers in route match\n");
            return false;
        }
        header_name = kmesh_get_ptr_val(header_match->name);
        if (!header_name) {
            BPF_LOG(ERR, ROUTER_CONFIG, "failed to get match headers in route match\n");
            return false;
        }
        msg_header = (struct bpf_mem_ptr *)bpf_get_msg_header_element(header_name);
        if (!msg_header) {
            BPF_LOG(DEBUG, ROUTER_CONFIG, "failed to get header value form msg\n");
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

static inline int
virtual_host_route_match_check(Route__Route *route, address_t *addr, ctx_buff_t *ctx, struct bpf_mem_ptr *msg)
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

    if (bpf_strnstr(ptr, prefix, BPF_DATA_MAX_LEN) == NULL)
        return 0;

    if (!check_headers_match(match))
        return 0;

    BPF_LOG(DEBUG, ROUTER_CONFIG, "match route, name=\"%s\"\n", (char *)kmesh_get_ptr_val(route->name));
    return 1;
}

static inline Route__Route *
virtual_host_route_match(Route__VirtualHost *virt_host, address_t *addr, ctx_buff_t *ctx, struct bpf_mem_ptr *msg)
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

        route = (Route__Route *)kmesh_get_ptr_val((void *)*((__u64 *)ptrs + i));
        if (!route)
            continue;

        if (virtual_host_route_match_check(route, addr, ctx, msg))
            return route;
    }
    return NULL;
}

static inline char *select_weight_cluster(Route__RouteAction *route_act)
{
    void *ptr = NULL;
    Route__WeightedCluster *weightedCluster = NULL;
    Route__ClusterWeight *route_cluster_weight = NULL;
    int32_t select_value;
    void *cluster_name = NULL;

    weightedCluster = kmesh_get_ptr_val((route_act->weighted_clusters));
    if (!weightedCluster) {
        return NULL;
    }
    ptr = kmesh_get_ptr_val(weightedCluster->clusters);
    if (!ptr) {
        return NULL;
    }
    select_value = (int)(bpf_get_prandom_u32() % 100);
    for (int i = 0; i < KMESH_PER_WEIGHT_CLUSTER_NUM; i++) {
        if (i >= weightedCluster->n_clusters) {
            break;
        }
        route_cluster_weight = (Route__ClusterWeight *)kmesh_get_ptr_val((void *)*((__u64 *)ptr + i));
        if (!route_cluster_weight) {
            return NULL;
        }
        select_value = select_value - (int)route_cluster_weight->weight;
        if (select_value <= 0) {
            cluster_name = kmesh_get_ptr_val(route_cluster_weight->name);
            BPF_LOG(
                DEBUG,
                ROUTER_CONFIG,
                "select cluster, name:weight %s:%d\n",
                cluster_name,
                route_cluster_weight->weight);
            return cluster_name;
        }
    }
    return NULL;
}

static inline char *route_get_cluster(const Route__Route *route)
{
    Route__RouteAction *route_act = NULL;
    route_act = kmesh_get_ptr_val(_(route->route));
    if (!route_act) {
        BPF_LOG(ERR, ROUTER_CONFIG, "failed to get route action ptr\n");
        return NULL;
    }

    if (route_act->cluster_specifier_case == ROUTE__ROUTE_ACTION__CLUSTER_SPECIFIER_WEIGHTED_CLUSTERS) {
        return select_weight_cluster(route_act);
    }

    return kmesh_get_ptr_val(_(route_act->cluster));
}

SEC_TAIL(KMESH_PORG_CALLS, KMESH_TAIL_CALL_ROUTER_CONFIG)
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

    KMESH_TAIL_CALL_CTX_KEY(ctx_key, KMESH_TAIL_CALL_ROUTER_CONFIG, addr);
    ctx_val = kmesh_tail_lookup_ctx(&ctx_key);
    if (!ctx_val)
        return KMESH_TAIL_CALL_RET(-1);

    route_config = map_lookup_route_config(ctx_val->data);
    kmesh_tail_delete_ctx(&ctx_key);
    if (!route_config) {
        BPF_LOG(WARN, ROUTER_CONFIG, "failed to lookup route config, route_name=\"%s\"\n", ctx_val->data);
        return KMESH_TAIL_CALL_RET(-1);
    }

    virt_host = virtual_host_match(route_config, &addr, ctx);
    if (!virt_host) {
        BPF_LOG(ERR, ROUTER_CONFIG, "failed to match virtual host, addr=%u\n", addr.ipv4);
        return KMESH_TAIL_CALL_RET(-1);
    }

    route = virtual_host_route_match(virt_host, &addr, ctx, (struct bpf_mem_ptr *)ctx_val->msg);
    if (!route) {
        BPF_LOG(ERR, ROUTER_CONFIG, "failed to match route action, addr=%u\n", addr.ipv4);
        return KMESH_TAIL_CALL_RET(-1);
    }

    cluster = route_get_cluster(route);
    if (!cluster) {
        BPF_LOG(ERR, ROUTER_CONFIG, "failed to get cluster\n");
        return KMESH_TAIL_CALL_RET(-1);
    }

    KMESH_TAIL_CALL_CTX_KEY(ctx_key, KMESH_TAIL_CALL_CLUSTER, addr);
    KMESH_TAIL_CALL_CTX_VALSTR(ctx_val_1, NULL, cluster);

    KMESH_TAIL_CALL_WITH_CTX(KMESH_TAIL_CALL_CLUSTER, ctx_key, ctx_val_1);
    return KMESH_TAIL_CALL_RET(ret);
}
#endif
