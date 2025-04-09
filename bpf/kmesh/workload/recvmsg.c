// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <sys/socket.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bpf_log.h"
#include "encoder.h"
#include "bpf_common.h"
#include "probe.h"

static inline bool is_managed_by_kmesh_skb(struct __sk_buff *skb)
{
    struct manager_key key = {0};
    if (skb->family == AF_INET)
        key.addr.ip4 = skb->local_ip4;
    if (skb->family == AF_INET6) {
        if (is_ipv4_mapped_addr(skb->local_ip6))
            key.addr.ip4 = skb->local_ip6[3];
        else
            IP6_COPY(key.addr.ip6, skb->local_ip6);
    }

    int *value = bpf_map_lookup_elem(&map_of_manager, &key);
    if (!value)
        return false;
    return (*value == 0);
}

SEC("sk_skb")
int recvmsg_prog(struct __sk_buff *skb)
{
    if (skb->family != AF_INET && skb->family != AF_INET6)
        return SK_PASS;

    struct bpf_sock *sk = skb->sk;
    __u32 size = skb->len;

    if (sk) {
        if (is_managed_by_kmesh_skb(skb)) {
            // observe_on_data(sk, size, RECV);
            // report_after_threshold_tm(sk);
        }
    } else {
        BPF_LOG(ERR, KMESH, "sk is nil\n");
    }

    return SK_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;