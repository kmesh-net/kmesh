// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_PROBE_H__
#define __KMESH_BPF_PROBE_H__

#include "tcp_probe.h"

static inline void observe_on_pre_connect(struct bpf_sock *sk)
{
    struct sock_storage_data *storage = NULL;
    if (!sk)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "pre_connect bpf_sk_storage_get failed\n");
        return;
    }

    storage->connect_ns = bpf_ktime_get_ns();
    return;
}

static inline void observe_on_connect_established(struct bpf_sock *sk, __u8 direction)
{
    struct bpf_tcp_sock *tcp_sock = NULL;
    struct sock_storage_data *storage = NULL;
    __u64 flags = (direction == OUTBOUND) ? 0 : BPF_LOCAL_STORAGE_GET_F_CREATE;

    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, flags);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "connect bpf_sk_storage_get failed\n");
        return;
    }

    // INBOUND scenario
    if (direction == INBOUND)
        storage->connect_ns = bpf_ktime_get_ns();
    storage->direction = direction;
    storage->connect_success = true;

    tcp_report(sk, tcp_sock, storage, BPF_TCP_ESTABLISHED);
}

static inline void observe_on_close(struct bpf_sock *sk)
{
    struct bpf_tcp_sock *tcp_sock = NULL;
    struct sock_storage_data *storage = NULL;
    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        __u32 src_ip4 = sk->src_ip4;
        __u32 dst_ip4 = sk->dst_ip4;
        __u32 src_port = sk->src_port;
        __u32 dst_port = (__u32)bpf_ntohs(sk->dst_port);

        if (sk->family == AF_INET) {
            // IPv4 连接
            BPF_LOG(INFO, PROBE, "TCP connection closed, src_ip=%u.%u.%u.%u, src_port=%u, dst_ip=%u.%u.%u.%u, dst_port=%u\n",
                    (src_ip4 >> 24) & 0xFF, (src_ip4 >> 16) & 0xFF, (src_ip4 >> 8) & 0xFF, src_ip4 & 0xFF,
                    src_port,
                    (dst_ip4 >> 24) & 0xFF, (dst_ip4 >> 16) & 0xFF, (dst_ip4 >> 8) & 0xFF, dst_ip4 & 0xFF,
                    dst_port);
        } else if (sk->family == AF_INET6) {
            // IPv6 连接
            __u32 src_ip6_0 = bpf_ntohl(sk->src_ip6[0]);
            __u32 src_ip6_1 = bpf_ntohl(sk->src_ip6[1]);
            __u32 src_ip6_2 = bpf_ntohl(sk->src_ip6[2]);
            __u32 src_ip6_3 = bpf_ntohl(sk->src_ip6[3]);
            __u32 dst_ip6_0 = bpf_ntohl(sk->dst_ip6[0]);
            __u32 dst_ip6_1 = bpf_ntohl(sk->dst_ip6[1]);
            __u32 dst_ip6_2 = bpf_ntohl(sk->dst_ip6[2]);
            __u32 dst_ip6_3 = bpf_ntohl(sk->dst_ip6[3]);

            BPF_LOG(INFO, PROBE, "TCP connection closed, src_ip=%x:%x:%x:%x, src_port=%u, dst_ip=%x:%x:%x:%x, dst_port=%u\n",
                    src_ip6_0, src_ip6_1, src_ip6_2, src_ip6_3,
                    src_port,
                    dst_ip6_0, dst_ip6_1, dst_ip6_2, dst_ip6_3,
                    dst_port);
        }
        return;
    }

    tcp_report(sk, tcp_sock, storage, BPF_TCP_CLOSE);
}
#endif
