/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: nlgwcy
 * Create: 2022-02-14
 */
#ifndef __KMESH_LISTENER_H__
#define __KMESH_LISTENER_H__

#include "kmesh_common.h"
#include "tail_call.h"
#include "listener/listener.pb-c.h"

bpf_map_t SEC("maps") map_of_listener = {
    .type               = BPF_MAP_TYPE_HASH,
    .key_size           = sizeof(address_t),
    .value_size         = sizeof(Listener__Listener),
    .max_entries        = MAP_SIZE_OF_LISTENER,
    .map_flags          = 0,
};

static inline
Listener__Listener * map_lookup_listener(const address_t *addr)
{
    return kmesh_map_lookup_elem(&map_of_listener, addr);
}

static inline
int listener_filter_chain_match_check(const Listener__FilterChain *filter_chain, 
                                      const address_t * addr, 
                                      const ctx_buff_t *ctx)
{
    Listener__FilterChainMatch * filter_chain_match = kmesh_get_ptr_val(filter_chain->filter_chain_match);
    if (filter_chain_match && (filter_chain_match->destination_port == addr->port)) {
        return 1;
    }
    return 0;
}

static inline 
int listener_filter_chain_match(const Listener__Listener *listener, 
                                                    const address_t *addr, 
                                                    const ctx_buff_t *ctx,
                                                    Listener__FilterChain **filter_chain_ptr,
                                                    __u64 *filter_chain_idx)
{
    int i;
    void *ptrs = NULL;
    size_t n_filter_chains = listener->n_filter_chains;
    Listener__FilterChain *filter_chain = NULL;

    BPF_LOG(INFO, LISTENER, "enter listener_filter_chain_match\n");
    if (n_filter_chains == 0 || n_filter_chains > KMESH_PER_FILTER_CHAIN_NUM) {
        BPF_LOG(ERR, LISTENER, "listener has no filter chains\n");
        return -1;
    }

    ptrs = kmesh_get_ptr_val(listener->filter_chains);
    if (!ptrs) {
        BPF_LOG(ERR, LISTENER, "failed to get filter chain ptrs\n");
        return -1;
    }
    
    n_filter_chains = BPF_MIN(n_filter_chains, KMESH_PER_FILTER_CHAIN_NUM);
#pragma unroll
    for (i = 0; i < n_filter_chains; i++) {
        filter_chain = (Listener__FilterChain *)kmesh_get_ptr_val(_(ptrs + i));
        if (!filter_chain) {
            continue;
        }

        if (listener_filter_chain_match_check(filter_chain, addr, ctx)) {
            *filter_chain_ptr = filter_chain;
            *filter_chain_idx = (__u64)_(ptrs + i);
            return 0;
        }
    }
    return -1;
}

static inline 
int l7_listener_manager(ctx_buff_t *ctx, Listener__Listener *listener)
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
        return -1;
    }
    
    /* exec filter chain */
    ctx_key.address = addr;
    ctx_key.tail_call_index = KMESH_TAIL_CALL_FILTER_CHAIN;
    ctx_val.val = filter_chain_idx;
    ret = kmesh_tail_update_ctx(&ctx_key, &ctx_val);
    if (ret != 0) {
        BPF_LOG(ERR, LISTENER, "kmesh tail update failed:%d\n", ret);
        return ret;
    }

    kmesh_tail_call(ctx, KMESH_TAIL_CALL_FILTER_CHAIN);
    kmesh_tail_delete_ctx(&ctx_key);

    BPF_LOG(ERR, LISTENER, "l7_listener_manager exit\n");
    return ret;
}
#endif
