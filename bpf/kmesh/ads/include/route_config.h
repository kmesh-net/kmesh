/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __ROUTE_CONFIG_H__
#define __ROUTE_CONFIG_H__

#include "bpf_log.h"
#include "kmesh_common.h"
#include "tail_call.h"
#include "route/route.pb-c.h"
#include "config.h"

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
virtual_host_match_check(Route__VirtualHost *virt_host, char *addr, ctx_buff_t *ctx, char *host_key, int host_key_len)
{
    int i;
    void *domains = NULL;
    void *domain = NULL;
    void *ptr;
    __u32 ptr_length;

    if (!virt_host->domains || !addr)
        return 0;

    domains = KMESH_GET_PTR_VAL(_(virt_host->domains), void *);
    if (!domains)
        return 0;

    for (i = 0; i < KMESH_HTTP_DOMAIN_NUM; i++) {
        if (i >= virt_host->n_domains) {
            break;
        }

        domain = KMESH_GET_PTR_VAL((void *)*((__u64 *)domains + i), char *);
        if (!domain)
            continue;

        if (((char *)domain)[0] == '*' && ((char *)domain)[1] == '\0')
            return 1;

        if (bpf_km_header_strnstr(ctx, host_key, host_key_len, domain, BPF_DATA_MAX_LEN)) {
            return 1;
        } else {
            if (bpf__strncmp(addr, BPF_DATA_MAX_LEN, domain) == 0) {
                return 1;
            }
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
    int host_key_len = 5;

    if (route_config->n_virtual_hosts <= 0 || route_config->n_virtual_hosts > KMESH_PER_VIRT_HOST_NUM) {
        BPF_LOG(WARN, ROUTER_CONFIG, "invalid virt hosts num=%d\n", route_config->n_virtual_hosts);
        return NULL;
    }

    ptrs = KMESH_GET_PTR_VAL(_(route_config->virtual_hosts), void *);
    if (!ptrs) {
        BPF_LOG(ERR, ROUTER_CONFIG, "failed to get virtual hosts\n");
        return NULL;
    }

    for (i = 0; i < KMESH_PER_VIRT_HOST_NUM; i++) {
        if (i >= route_config->n_virtual_hosts) {
            break;
        }

        virt_host = KMESH_GET_PTR_VAL((void *)*((__u64 *)ptrs + i), Route__VirtualHost);
        if (!virt_host)
            continue;

        if (VirtualHost_check_allow_any((char *)KMESH_GET_PTR_VAL(virt_host->name, char *))) {
            virt_host_allow_any = virt_host;
            continue;
        }

        if (virtual_host_match_check(virt_host, addr, ctx, host_key, host_key_len)) {
            BPF_LOG(
                DEBUG,
                ROUTER_CONFIG,
                "match virtual_host, name=\"%s\"\n",
                (char *)KMESH_GET_PTR_VAL(virt_host->name, char *));
            return virt_host;
        }
    }
    // allow_any as the default virt_host
    if (virt_host_allow_any && virtual_host_match_check(virt_host_allow_any, addr, ctx, host_key, host_key_len))
        return virt_host_allow_any;
    return NULL;
}

static inline bool check_header_value_match(char *target, char *header_name, bool exact)
{
    int ret = 0;
    ret = bpf_km_header_strncmp(header_name, BPF_DATA_MAX_LEN, target, BPF_DATA_MAX_LEN, exact);
    if (ret != 0)
        return false;
    return true;
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
    ptrs = KMESH_GET_PTR_VAL(_(match->headers), void *);
    if (!ptrs) {
        BPF_LOG(ERR, ROUTER_CONFIG, "failed to get match headers in route match\n");
        return false;
    }
    for (i = 0; i < KMESH_PER_HEADER_MUM; i++) {
        if (i >= match->n_headers) {
            break;
        }
        header_match = (Route__HeaderMatcher *)KMESH_GET_PTR_VAL((void *)*((__u64 *)ptrs + i), Route__HeaderMatcher);
        if (!header_match) {
            BPF_LOG(ERR, ROUTER_CONFIG, "failed to get match headers in route match\n");
            return false;
        }
        header_name = KMESH_GET_PTR_VAL(header_match->name, char *);
        if (!header_name) {
            BPF_LOG(ERR, ROUTER_CONFIG, "failed to get match headers in route match\n");
            return false;
        }

        switch (header_match->header_match_specifier_case) {
        case ROUTE__HEADER_MATCHER__HEADER_MATCH_SPECIFIER_EXACT_MATCH: {
            config_header_value = KMESH_GET_PTR_VAL(header_match->exact_match, char *);
            if (config_header_value == NULL) {
                BPF_LOG(ERR, ROUTER_CONFIG, "failed to get config_header_value\n");
                return false;
            }
            if (!check_header_value_match(config_header_value, header_name, true)) {
                return false;
            }
            break;
        }
        case ROUTE__HEADER_MATCHER__HEADER_MATCH_SPECIFIER_PREFIX_MATCH: {
            config_header_value = KMESH_GET_PTR_VAL(header_match->prefix_match, char *);
            if (config_header_value == NULL) {
                BPF_LOG(ERR, ROUTER_CONFIG, "prefix:failed to get config_header_value\n");
                return false;
            }
            if (!check_header_value_match(config_header_value, header_name, false)) {
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
    char uri[4] = {'U', 'R', 'I', '\0'};
    int uri_len = 4;

    if (!route->match)
        return 0;

    match = KMESH_GET_PTR_VAL(route->match, Route__RouteMatch);
    if (!match)
        return 0;

    prefix = KMESH_GET_PTR_VAL(match->prefix, char *);
    if (!prefix)
        return 0;

    if (!bpf_km_header_strnstr(ctx, uri, uri_len, prefix, BPF_DATA_MAX_LEN)) {
        return 0;
    }

    if (!check_headers_match(match))
        return 0;

    BPF_LOG(DEBUG, ROUTER_CONFIG, "match route, name=\"%s\"\n", (char *)KMESH_GET_PTR_VAL(route->name, char *));
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

    ptrs = KMESH_GET_PTR_VAL(_(virt_host->routes), void *);
    if (!ptrs) {
        BPF_LOG(ERR, ROUTER_CONFIG, "failed to get routes ptrs\n");
        return NULL;
    }

    for (i = 0; i < KMESH_PER_ROUTE_NUM; i++) {
        if (i >= virt_host->n_routes) {
            break;
        }

        route = (Route__Route *)KMESH_GET_PTR_VAL((void *)*((__u64 *)ptrs + i), Route__Route);
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

    weightedCluster = KMESH_GET_PTR_VAL((route_act->weighted_clusters), Route__WeightedCluster);
    if (!weightedCluster) {
        return NULL;
    }
    ptr = KMESH_GET_PTR_VAL(weightedCluster->clusters, void *);
    if (!ptr) {
        return NULL;
    }
    select_value = (int)(bpf_get_prandom_u32() % 100);
    for (int i = 0; i < KMESH_PER_WEIGHT_CLUSTER_NUM; i++) {
        if (i >= weightedCluster->n_clusters) {
            break;
        }
        route_cluster_weight =
            (Route__ClusterWeight *)KMESH_GET_PTR_VAL((void *)*((__u64 *)ptr + i), Route__ClusterWeight);
        if (!route_cluster_weight) {
            return NULL;
        }
        select_value = select_value - (int)route_cluster_weight->weight;
        if (select_value <= 0) {
            cluster_name = KMESH_GET_PTR_VAL(route_cluster_weight->name, char *);
            break;
        }
    }

    if (cluster_name != NULL) {
        BPF_LOG(DEBUG, ROUTER_CONFIG, "selected cluster: %s\n", cluster_name);
        return cluster_name;
    }

    return NULL;
}

static inline char *route_get_cluster(const Route__Route *route)
{
    Route__RouteAction *route_act = NULL;
    route_act = KMESH_GET_PTR_VAL(_(route->route), Route__RouteAction);
    if (!route_act) {
        BPF_LOG(ERR, ROUTER_CONFIG, "failed to get route action ptr\n");
        return NULL;
    }

    if (route_act->cluster_specifier_case == ROUTE__ROUTE_ACTION__CLUSTER_SPECIFIER_WEIGHTED_CLUSTERS) {
        return select_weight_cluster(route_act);
    }

    return KMESH_GET_PTR_VAL(_(route_act->cluster), char *);
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
        BPF_LOG(ERR, ROUTER_CONFIG, "failed to match virtual host, addr=%s\n", ip2str(&addr.ipv4, 1));
        return KMESH_TAIL_CALL_RET(-1);
    }

    BPF_LOG(
        DEBUG, ROUTER_CONFIG, "match virtual_host, name=\"%s\"\n", (char *)KMESH_GET_PTR_VAL(virt_host->name, char *));

    route = virtual_host_route_match(virt_host, &addr, ctx, (struct bpf_mem_ptr *)ctx_val->msg);
    if (!route) {
        BPF_LOG(ERR, ROUTER_CONFIG, "failed to match route action, addr=%s\n", ip2str(&addr.ipv4, 1));
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
