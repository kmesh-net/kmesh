/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

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

#pragma unroll
    for (int i = 0; i < KMESH_PER_WEIGHT_CLUSTER_NUM; i++) {
        if (i >= weightedClusters->n_clusters) {
            break;
        }
        cluster_weight =
            (Filter__TcpProxy__WeightedCluster__ClusterWeight *)kmesh_get_ptr_val((void *)*((__u64 *)clusters + i));
        if (!cluster_weight) {
            return NULL;
        }
        select_value = select_value - (int)cluster_weight->weight;
        if (select_value <= 0) {
            cluster_name = kmesh_get_ptr_val(cluster_weight->name);
            BPF_LOG(DEBUG, FILTER, "select cluster, %s:%d\n", cluster_name, cluster_weight->weight);
            return (char *)cluster_name;
        }
    }
    return NULL;
}

static inline char *tcp_proxy_get_cluster(const Filter__TcpProxy *tcpProxy)
{
    if (tcpProxy->cluster_specifier_case == FILTER__TCP_PROXY__CLUSTER_SPECIFIER_WEIGHTED_CLUSTERS) {
        return select_tcp_weight_cluster(tcpProxy);
    }

    return (char *)kmesh_get_ptr_val(tcpProxy->cluster);
}

static inline int tcp_proxy_manager(const Filter__TcpProxy *tcpProxy, ctx_buff_t *ctx)
{
    int ret;
    char *cluster = NULL;
    ctx_key_t ctx_key = {0};
    ctx_val_t ctx_val = {0};

    if (NULL == tcpProxy)
        return -EINVAL;

    DECLARE_VAR_ADDRESS(ctx, addr);
    cluster = tcp_proxy_get_cluster(tcpProxy);

    KMESH_TAIL_CALL_CTX_KEY(ctx_key, KMESH_TAIL_CALL_CLUSTER, addr);
    KMESH_TAIL_CALL_CTX_VALSTR(ctx_val, NULL, cluster);

    KMESH_TAIL_CALL_WITH_CTX(KMESH_TAIL_CALL_CLUSTER, ctx_key, ctx_val);
    return KMESH_TAIL_CALL_RET(ret);
}

#endif // __TCP_PROXY_H__
