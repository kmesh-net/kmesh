// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <sys/socket.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "bpf_log.h"
#include "bpf_common.h"
#include "probe.h"
#include "config.h"

volatile __u32 enable_periodic_report = 0;

static inline bool is__periodic_report_enable()
{
    return enable_periodic_report == 1;
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress_prog(struct __sk_buff *skb)
{
    if (!is_monitoring_enable() || !is__periodic_report_enable()) {
        return SK_PASS;
    }
    if (skb->family != AF_INET && skb->family != AF_INET6)
        return SK_PASS;

    struct bpf_sock *sk = skb->sk;
    if (!sk)
        return SK_PASS;

    if (sock_conn_from_sim(skb)) {
        return SK_PASS;
    }

    if (!is_managed_by_kmesh_skb(skb))
        return SK_PASS;

    observe_on_data(sk);
    return SK_PASS;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress_prog(struct __sk_buff *skb)
{
    if (!is_monitoring_enable() || !is__periodic_report_enable()) {
        return SK_PASS;
    }
    if (skb->family != AF_INET && skb->family != AF_INET6)
        return SK_PASS;

    struct bpf_sock *sk = skb->sk;
    if (!sk)
        return SK_PASS;

    if (sock_conn_from_sim(skb)) {
        return SK_PASS;
    }

    if (!is_managed_by_kmesh_skb(skb))
        return SK_PASS;

    observe_on_data(sk);
    return SK_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;