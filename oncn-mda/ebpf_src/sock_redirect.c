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
 */

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

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
