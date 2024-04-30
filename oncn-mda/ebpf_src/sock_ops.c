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

#include <stddef.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "mesh_accelerate.h"

static bool is_accept_ip(__u32 ip4, const struct cidr *const param, bool filter_option)
{
    __u32 mask = bpf_htonl(param->mask);
    __u32 cidr_net = bpf_htonl(param->ip4) & mask;
    __u32 cidr_net_ip4 = ip4 & mask;
    bpf_log(DEBUG, "param ip:%u, mask:%u\n", bpf_htonl(param->ip4), mask);
    bpf_log(DEBUG, "ip: cidrs:%u, cidr_net:%u\n", cidr_net, cidr_net_ip4);
    if (cidr_net == cidr_net_ip4)
        return filter_option;
    return !filter_option;
}

static bool is_accept_port(
    const struct sock_key *const key,
    const struct sock_key *const peer_key,
    const struct port_range *const param,
    bool filter_option)
{
    __u32 begin_port = param->begin_port;
    __u32 end_port = param->end_port;
    __u32 input_sport = bpf_ntohl((key->sport) << FORMAT_IP_LENGTH);
    __u32 input_dport = bpf_ntohl((key->dport) << FORMAT_IP_LENGTH);
    __u32 input_peer_sport = bpf_ntohl((peer_key->sport) << FORMAT_IP_LENGTH);
    __u32 input_peer_dport = bpf_ntohl((peer_key->dport) << FORMAT_IP_LENGTH);
    bool sport = (begin_port <= input_sport) && (end_port >= input_sport);
    bool dport = (begin_port <= input_dport) && (end_port >= input_dport);
    bool peer_sport = (begin_port <= input_peer_sport) && (end_port >= input_peer_sport);
    bool peer_dport = (begin_port <= input_peer_dport) && (end_port >= input_peer_dport);
    if (sport || dport || peer_sport || peer_dport)
        return filter_option;
    return !filter_option;
}

static bool adj_filter_ip(__u32 ip4, const struct input_cidr *const param, bool filter_flag)
{
    for (int i = 0; i < MAX_PARAM_LENGTH; ++i) {
        if (i >= param->current_cidr_num)
            break;
        if (is_accept_ip(ip4, &param->cidrs[i], filter_flag) == filter_flag)
            return filter_flag;
    }
    return !filter_flag;
}

static bool filter_ip(
    const struct sock_key *const key,
    const struct sock_key *const peer_key,
    const struct input_cidr *const param,
    bool filter_flag)
{
    // If filter_flag is FILTER_PASS, the four IP addresses in key and peerkey must be in the whitelist
    // If filter_flag is FILTER_RETURN, an IP address in the key or peerKey is in the blacklist will be
    // return FILTER_RETURN
    if (param->current_cidr_num == 0)
        return FILTER_PASS;

    if (adj_filter_ip(key->sip4, param, filter_flag) != FILTER_PASS)
        return FILTER_RETURN;
    if (adj_filter_ip(key->dip4, param, filter_flag) != FILTER_PASS)
        return FILTER_RETURN;
    if (adj_filter_ip(peer_key->sip4, param, filter_flag) != FILTER_PASS)
        return FILTER_RETURN;
    if (adj_filter_ip(peer_key->dip4, param, filter_flag) != FILTER_PASS)
        return FILTER_RETURN;
    return FILTER_PASS;
}

static bool filter_port(
    const struct sock_key *const key,
    const struct sock_key *const peer_key,
    const struct input_port *const param,
    bool filter_flag)
{
    // If filter_flag is FILTER_PASS, any of the four ports in key and peerkey can pass the whitelist
    // If filter_flag is FILTER_RETURN, any of the four ports in key and peerkey cannot pass the blacklist
    if (param->current_port_num == 0)
        return FILTER_PASS;

    for (int i = 0; i < MAX_PARAM_LENGTH; ++i) {
        if (i >= param->current_port_num)
            break;
        if (is_accept_port(key, peer_key, &param->ports[i], filter_flag) == filter_flag)
            return filter_flag;
    }
    return !filter_flag;
}

#if MDA_GID_UID_FILTER
static bool is_accept_uid(const struct uid_gid_info *const current_uid_gid, const __u32 input_uid, bool filter_option)
{
    if ((current_uid_gid->cuid == input_uid) || (current_uid_gid->puid == input_uid))
        return filter_option;
    return !filter_option;
}

static bool is_accept_gid(const struct uid_gid_info *const current_uid_gid, const __u32 input_gid, bool filter_option)
{
    if ((current_uid_gid->cgid == input_gid) || (current_uid_gid->pgid == input_gid))
        return filter_option;
    return !filter_option;
}

static bool
filter_uid(const struct uid_gid_info *const current_uid_gid, const struct input_uid *const param, bool filter_flag)
{
    // If filter_flag is FILTER_PASS, either side of the UID can pass the whitelist
    // If filter_flag is FILTER_RETURN, either side of the UID cannot pass the blacklist
    if (param->current_uid_num == 0)
        return FILTER_PASS;
    for (int i = 0; i < MAX_PARAM_LENGTH; ++i) {
        if (i >= param->current_uid_num)
            break;
        if (is_accept_uid(current_uid_gid, param->uids[i], filter_flag) == filter_flag)
            return filter_flag;
    }
    return !filter_flag;
}

static bool
filter_gid(const struct uid_gid_info *const current_uid_gid, const struct input_gid *const param, bool filter_flag)
{
    // If filter_flag is FILTER_PASS, either gid can pass the whitelist
    // If filter_flag is FILTER_RETURN, either gid cannot pass the blacklist
    if (param->current_gid_num == 0)
        return FILTER_PASS;
    for (int i = 0; i < MAX_PARAM_LENGTH; ++i) {
        if (i >= param->current_gid_num)
            break;
        if (is_accept_gid(current_uid_gid, param->gids[i], filter_flag) == filter_flag)
            return filter_flag;
    }
    return !filter_flag;
}

static void get_current_uid_gid(struct uid_gid_info *const current_uid_gid, struct bpf_sock_ops *const skops)
{
    __u64 uid_gid = bpf_get_sockops_uid_gid(skops);
    current_uid_gid->cuid = (uid_gid & 0xffffffff);
    current_uid_gid->cgid = (uid_gid >> UID_LENGTH);
    current_uid_gid->puid = 0;
    current_uid_gid->pgid = 0;
}

static int get_peer_uid_gid(const struct sock_key *const peer_key, struct uid_gid_info *const current_uid_gid)
{
    struct uid_gid_info *peer_uid_gid = bpf_map_lookup_elem(&SOCK_OPS_HELPER_MAP_NAME, (void *)peer_key);
    if (peer_uid_gid == NULL) {
        return FAILED;
    } else {
        current_uid_gid->puid = peer_uid_gid->cuid;
        current_uid_gid->pgid = peer_uid_gid->cgid;
    }
    // Delete information about the peer Uid_GID in the helper
    bpf_map_delete_elem(&SOCK_OPS_HELPER_MAP_NAME, (void *)peer_key);
    return SUCCESS;
}
#endif

static bool
filter(const struct sock_key *const key, const struct sock_key *const peer_key, struct bpf_sock_ops *const skops)
{
    int index = 0;
    struct sock_param *param = bpf_map_lookup_elem(&SOCK_PARAM_MAP_NAME, &index);
    if (param == NULL)
        return FILTER_RETURN;
    if (filter_ip(key, peer_key, &param->return_cidrs, FILTER_RETURN) != FILTER_PASS)
        return FILTER_RETURN;

    if (filter_ip(key, peer_key, &param->accept_cidrs, FILTER_PASS) != FILTER_PASS)
        return FILTER_RETURN;

    if (filter_port(key, peer_key, &param->return_ports, FILTER_RETURN) != FILTER_PASS)
        return FILTER_RETURN;

    if (filter_port(key, peer_key, &param->accept_ports, FILTER_PASS) != FILTER_PASS)
        return FILTER_RETURN;

#if MDA_GID_UID_FILTER
    if (param->accept_uids.current_uid_num == 0 && param->return_uids.current_uid_num == 0
        && param->accept_gids.current_gid_num == 0 && param->return_gids.current_gid_num == 0)
        return FILTER_PASS;

    struct uid_gid_info current_uid_gid = {0};
    get_current_uid_gid(&current_uid_gid, skops);
    if (get_peer_uid_gid(peer_key, &current_uid_gid) != SUCCESS) {
        // The UID and GID of the peer are not found. mey be in other node
        bpf_log(INFO, "can not found the peer helper info! peer key:%u:%u\n", peer_key->sport, peer_key->sip4);
        return FILTER_RETURN;
    }

    if (filter_uid(&current_uid_gid, &param->return_uids, FILTER_RETURN) != FILTER_PASS)
        return FILTER_RETURN;

    if (filter_uid(&current_uid_gid, &param->accept_uids, FILTER_PASS) != FILTER_PASS)
        return FILTER_RETURN;

    if (filter_gid(&current_uid_gid, &param->return_gids, FILTER_RETURN) != FILTER_PASS)
        return FILTER_RETURN;

    if (filter_gid(&current_uid_gid, &param->accept_gids, FILTER_PASS) != FILTER_PASS)
        return FILTER_RETURN;
#endif

    return FILTER_PASS;
}

static void extract_key4_from_ops(struct bpf_sock_ops *const ops, struct sock_key *const key)
{
    key->sip4 = ops->local_ip4;
    /*
     * The reason for the 16-bit shift to the right is that clang-7.1 and later versions seem to be
     * optimized to think that only 16-bit data needs to be read here, but most kernels do not support this,
     * causing the BPF validator to fail.
     */
    key->sport = (bpf_htonl(ops->local_port) >> FORMAT_IP_LENGTH);
    key->dip4 = ops->remote_ip4;

#if !OE_23_03
    key->dport = (force_read(ops->remote_port) >> FORMAT_IP_LENGTH);
#else
    key->dport = (force_read(ops->remote_port));
#endif
    bpf_log(DEBUG, "sip:%u, sport:%u\n", key->sip4, key->sport);
    bpf_log(DEBUG, "dip:%u, dport:%u\n", key->dip4, key->dport);

#if MDA_LOOPBACK_ADDR
    set_netns_cookie((void *)ops, key);
    bpf_log(DEBUG, "netns_cookie:%u\n", key->netns_cookie);
#endif
}

static int add_sockhash_map(struct bpf_sock_ops *const skops, const struct sock_key *const key)
{
    long ret = bpf_sock_hash_update((void *)skops, &SOCK_OPS_MAP_NAME, (void *)key, BPF_ANY);
    if (ret != 0) {
        bpf_log(ERROR, "sock ops map operator failed! err is %d\n", ret);
        return FAILED;
    }
    return SUCCESS;
}

#if MDA_GID_UID_FILTER
static int add_helper_hash(const struct sock_key *const key, const struct uid_gid_info *const uid_gid)
{
    long ret = bpf_map_update_elem(&SOCK_OPS_HELPER_MAP_NAME, (void *)key, (void *)uid_gid, BPF_ANY);
    if (ret != 0) {
        bpf_log(DEBUG, "add_helper_hash failed! sip:%u, sport:%u ret:%d\n", key->sip4, key->sport, ret);
        return FAILED;
    }
    return SUCCESS;
}
#endif

static int
get_peer_addr(struct bpf_sock_ops *const skops, const struct sock_key *const key, struct sock_key *const peer_key)
{
#if MDA_NAT_ACCEL
    struct sockaddr_in target = {0};
    int target_len = sizeof(target);
    int ret = bpf_sk_original_addr(skops, SO_ORIGINAL_DST, (void *)&target, target_len);
    if (ret == 0) {
        peer_key->sip4 = key->dip4;
        peer_key->sport = key->dport;
        peer_key->dip4 = target.sin_addr.s_addr;
        peer_key->dport = target.sin_port;
#if MDA_LOOPBACK_ADDR
        set_netns_cookie((void *)skops, peer_key);
#endif
        return SUCCESS;
    } else if (ret == -ENOENT) {
#endif
        peer_key->sip4 = key->dip4;
        peer_key->sport = key->dport;
        peer_key->dip4 = key->sip4;
        peer_key->dport = key->sport;
#if MDA_LOOPBACK_ADDR
        set_netns_cookie((void *)skops, peer_key);
#endif
        return SUCCESS;
#if MDA_NAT_ACCEL
    }

    bpf_log(ERROR, "get target failed!, operator = %d, ret = %d\n", SO_ORIGINAL_DST, ret);
    return FAILED;
#endif
}

static int clean_ops(const struct sock_key *const key)
{
    bpf_map_delete_elem(&SOCK_OPS_MAP_NAME, (void *)key);
#if MDA_GID_UID_FILTER
    bpf_map_delete_elem(&SOCK_OPS_HELPER_MAP_NAME, (void *)key);
#endif
    bpf_map_delete_elem(&SOCK_OPS_PROXY_MAP_NAME, (void *)key);
    return SUCCESS;
}

static void active_ops_ipv4(struct bpf_sock_ops *const skops)
{
    struct sock_key key = {0};
    extract_key4_from_ops(skops, &key);
    if (add_sockhash_map(skops, &key)) {
        bpf_log(ERROR, "active_ops_ipv4 failed!\n");
        return;
    }

#if MDA_GID_UID_FILTER
    struct uid_gid_info current_uid_gid = {0};
    get_current_uid_gid(&current_uid_gid, skops);
    if (add_helper_hash(&key, &current_uid_gid)) {
        bpf_log(ERROR, "active_ops_ipv4 failed!\n");
        (void)clean_ops(&key);
        return;
    }
#endif
    return;
}

static void passive_ops_ipv4(struct bpf_sock_ops *const skops)
{
    struct sock_key key = {0};
    struct sock_key peer_key = {0};

    extract_key4_from_ops(skops, &key);

    if (get_peer_addr(skops, &key, &peer_key) != SUCCESS)
        goto err;

    if (filter(&key, &peer_key, skops) == FILTER_RETURN) {
        bpf_log(INFO, "sip:%u, sport:%u filtered\n", peer_key.sip4, peer_key.sport);
        goto err;
    }

    if (add_sockhash_map(skops, &key))
        goto err;

    /*
     * key:			 127.0.0.1:15001->172.17.0.3:6002
     * peer_key:		172.17.0.3:6002->172.17.0.2:5002
     */

    if (bpf_map_update_elem(&SOCK_OPS_PROXY_MAP_NAME, &key, &peer_key, BPF_ANY))
        goto err;

    if (bpf_map_update_elem(&SOCK_OPS_PROXY_MAP_NAME, &peer_key, &key, BPF_ANY))
        goto err;
    return;
err:
    (void)clean_ops(&peer_key);
    (void)clean_ops(&key);

    return;
}

static void clean_ops_map(struct bpf_sock_ops *const skops)
{
    struct sock_key key;
    struct sock_key *reverse_key = NULL;
    extract_key4_from_ops(skops, &key);
    int ret;

#if MDA_GID_UID_FILTER
    ret = bpf_map_delete_elem(&SOCK_OPS_HELPER_MAP_NAME, &key);
    if (ret && ret != -ENOENT)
        bpf_log(INFO, "bpf map delete helper elem key failed! ret:%d\n", ret);
#endif
    reverse_key = bpf_map_lookup_elem(&SOCK_OPS_PROXY_MAP_NAME, &key);
    ret = bpf_map_delete_elem(&SOCK_OPS_PROXY_MAP_NAME, &key);
    if (ret && ret != -ENOENT)
        bpf_log(INFO, "bpf map delete proxy elem key failed! ret:%d\n", ret);

    if (reverse_key == NULL)
        return;

    ret = bpf_map_delete_elem(&SOCK_OPS_PROXY_MAP_NAME, reverse_key);
    if (ret && ret != -ENOENT)
        bpf_log(INFO, "bpf map delete proxy elem key failed! ret:%d\n", ret);
}

SEC("sockops")
int SOCK_OPS_NAME(struct bpf_sock_ops *const skops)
{
    if (skops->family != AF_INET)
        return 0;

    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        bpf_log(DEBUG, "active\n");
        if (bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG) != 0)
            bpf_log(ERROR, "set sockops cb failed!\n");
        active_ops_ipv4(skops);
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        bpf_log(DEBUG, "passive\n");
        if (bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG) != 0)
            bpf_log(ERROR, "set sockops cb failed!\n");
        passive_ops_ipv4(skops);
        break;
    case BPF_SOCK_OPS_STATE_CB:
        if (skops->args[1] == BPF_TCP_CLOSE || skops->args[1] == BPF_TCP_CLOSE_WAIT
            || skops->args[1] == BPF_TCP_FIN_WAIT1)
            clean_ops_map(skops);
        break;
    default:
        break;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
