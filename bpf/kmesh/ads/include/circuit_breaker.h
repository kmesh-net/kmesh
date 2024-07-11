#include "bpf_log.h"
#include "kmesh_common.h"
#include "bpf_common.h"

#ifndef __KMESH_CIRCUIT_BREAKER_H__
#define __KMESH_CIRCUIT_BREAKER_H__

static inline void on_cluster_sock_bind(struct bpf_sock *sk, const char* cluster_name) {
    BPF_LOG(DEBUG, KMESH, "record sock bind for cluster %s\n", cluster_name);
    struct cluster_sock_data *data = NULL;
    if (!sk) {
        BPF_LOG(WARN, KMESH, "provided sock is NULL\n");
        return;
    }

    data = bpf_sk_storage_get(&map_of_cluster_sock, sk, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!data) {
        BPF_LOG(ERR, KMESH, "record_cluster_sock call bpf_sk_storage_get failed\n");
        return;
    }

    bpf_strncpy(data->cluster_name, BPF_DATA_MAX_LEN, (char *)cluster_name);
    BPF_LOG(DEBUG, KMESH, "record sock bind for cluster %s done\n", cluster_name);
}

static inline struct cluster_sock_data* get_cluster_sk_data(struct bpf_sock *sk) {
    struct cluster_sock_data *data = NULL;
    if (!sk) {
        BPF_LOG(DEBUG, KMESH, "provided sock is NULL\n");
        return NULL;
    }

    data = bpf_sk_storage_get(&map_of_cluster_sock, sk, 0, 0);
    return data;
}

static inline void on_cluster_sock_connect(struct bpf_sock *sk) {
    struct cluster_sock_data *data = get_cluster_sk_data(sk);
    if (!data) {
        return;
    }
    BPF_LOG(DEBUG, KMESH, "record sock connection for cluster %s\n", data->cluster_name);
}

static inline void on_cluster_sock_close(struct bpf_sock *sk) {
    struct cluster_sock_data *data = get_cluster_sk_data(sk);
    if (!data) {
        return;
    }
    BPF_LOG(DEBUG, KMESH, "record sock close for cluster %s", data->cluster_name);
}

#endif