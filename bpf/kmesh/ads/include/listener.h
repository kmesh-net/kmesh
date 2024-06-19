/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __KMESH_LISTENER_H__
#define __KMESH_LISTENER_H__

#include "kmesh_common.h"
#include "tail_call.h"
#include "listener/listener.pb-c.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(address_t));
    __uint(value_size, sizeof(Listener__Listener));
    __uint(max_entries, MAP_SIZE_OF_LISTENER);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_of_listener SEC(".maps");

static inline Listener__Listener *map_lookup_listener(const address_t *addr)
{
    return kmesh_map_lookup_elem(&map_of_listener, addr);
}

static inline bool listener_filter_chain_match_check(
    const Listener__FilterChain *filter_chain, const address_t *addr, const ctx_buff_t *ctx)
{
    char *transport_protocol;
    const char buf[] = "raw_buffer";

    Listener__FilterChainMatch *filter_chain_match = kmesh_get_ptr_val(filter_chain->filter_chain_match);
    if (!filter_chain_match)
        return false;

    if (filter_chain_match->destination_port != 0 && filter_chain_match->destination_port != addr->port)
        return false;

    transport_protocol = kmesh_get_ptr_val(filter_chain_match->transport_protocol);
    if (!transport_protocol) {
        BPF_LOG(WARN, LISTENER, "transport_protocol is NULL\n");
        return false;
    } else if (transport_protocol[0] != '\0' && bpf__strncmp(buf, sizeof(buf), transport_protocol) != 0) {
        BPF_LOG(WARN, LISTENER, "transport_protocol %s mismatch\n", transport_protocol);
        return false;
    }

    // TODO: application_protocols

    BPF_LOG(DEBUG, LISTENER, "match filter_chain, name=\"%s\"\n", (char *)kmesh_get_ptr_val(filter_chain->name));
    return true;
}

static inline int listener_filter_chain_match(
    const Listener__Listener *listener,
    const address_t *addr,
    const ctx_buff_t *ctx,
    Listener__FilterChain **filter_chain_ptr,
    __u64 *filter_chain_idx)
{
    int i;
    void *ptrs = NULL;
    Listener__FilterChain *filter_chain = NULL;

    if (listener->n_filter_chains == 0 || listener->n_filter_chains > KMESH_PER_FILTER_CHAIN_NUM) {
        BPF_LOG(ERR, LISTENER, "listener has no filter chains\n");
        return -1;
    }

    ptrs = kmesh_get_ptr_val(listener->filter_chains);
    if (!ptrs) {
        BPF_LOG(ERR, LISTENER, "failed to get filter chain ptrs\n");
        return -1;
    }

#pragma unroll
    for (i = 0; i < KMESH_PER_FILTER_CHAIN_NUM; i++) {
        if (i >= (int)listener->n_filter_chains) {
            break;
        }

        filter_chain = (Listener__FilterChain *)kmesh_get_ptr_val((void *)*((__u64 *)ptrs + i));
        if (!filter_chain) {
            continue;
        }

        if (listener_filter_chain_match_check(filter_chain, addr, ctx)) {
            *filter_chain_ptr = filter_chain;
            *filter_chain_idx = (__u64) * ((__u64 *)ptrs + i);
            return 0;
        }
    }
    return -1;
}

static inline int listener_manager(ctx_buff_t *ctx, Listener__Listener *listener, struct bpf_mem_ptr *msg)
{
    int ret = 0;
    __u64 filter_chain_idx = 0;
    Listener__FilterChain *filter_chain = NULL;
    ctx_key_t ctx_key = {0};
    ctx_val_t ctx_val = {0};

    DECLARE_VAR_ADDRESS(ctx, addr);
    /* filter chain match */
    ret = listener_filter_chain_match(listener, &addr, ctx, &filter_chain, &filter_chain_idx);
    if (ret != 0) {
        BPF_LOG(
            WARN,
            LISTENER,
            "filterchain mismatch, unsupport addr=%s:%u\n",
            ip2str(&addr.ipv4, 1),
            bpf_ntohs(addr.port));
        return -1;
    }

    /* exec filter chain */
    KMESH_TAIL_CALL_CTX_KEY(ctx_key, KMESH_TAIL_CALL_FILTER_CHAIN, addr);
    KMESH_TAIL_CALL_CTX_VAL(ctx_val, msg, filter_chain_idx);

    KMESH_TAIL_CALL_WITH_CTX(KMESH_TAIL_CALL_FILTER_CHAIN, ctx_key, ctx_val);
    return KMESH_TAIL_CALL_RET(ret);
}
#endif
