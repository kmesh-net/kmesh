// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include "mesh_accelerate.h"

SEC("sk_msg")
int SOCK_REDIRECT_NAME(struct sk_msg_md *const msg)
{
    struct sock_key key = {0};
    struct sock_key *redir_key = NULL;
    long ret = 0;

    key.sip4 = msg->local_ip4;
    key.dip4 = msg->remote_ip4;
    key.sport = (bpf_htonl(msg->local_port) >> 16);
    key.dport = (force_read(msg->remote_port) >> 16);
#if MDA_LOOPBACK_ADDR
    set_netns_cookie((void *)msg, &key);
#endif

    redir_key = bpf_map_lookup_elem(&SOCK_OPS_PROXY_MAP_NAME, &key);
    if (redir_key != NULL) {
        ret = bpf_msg_redirect_hash(msg, &SOCK_OPS_MAP_NAME, redir_key, BPF_F_INGRESS);
        if (ret != SK_DROP) {
            bpf_log(DEBUG, "redirect the sk success\n");

        } else {
            // If you connect to the peer machine, you do end up in this branch
            bpf_log(INFO, "no such socket, may be peer socket on another machine\n");
        }
    }

    return SK_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;
