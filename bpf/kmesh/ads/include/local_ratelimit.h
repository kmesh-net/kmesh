/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __KMESH_LOCAL_RATE_LIMIT_H__
#define __KMESH_LOCAL_RATE_LIMIT_H__

#include "bpf_log.h"
#include "bpf_common.h"
#include "kmesh_common.h"
#include "listener/listener.pb-c.h"

struct ratelimit_key {
    union {
        struct {
            __u32 ipv4;   /* Destination IPv4 address. */
            __u32 port;   /* Destination port. */
            __u32 family; /* Address family (e.g., AF_INET) */
        } sk_skb;
    } key;
};

struct ratelimit_value {
    __u64 last_topup; /* Timestamp of the last token refill (nanoseconds) */
    __u64 tokens;     /* Current number of available tokens */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ratelimit_key);
    __type(value, struct ratelimit_value);
    __uint(max_entries, 1000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_of_local_ratelimit SEC(".maps");

struct ratelimit_settings {
    __u64 bucket_size;       /* Maximum capacity of the token bucket */
    __u64 tokens_per_topup;  /* Number of tokens added per refill */
    __u64 topup_interval_ns; /* Interval between token refills (nanoseconds) */
};

/**
 * Enforces rate limiting for a given key using token bucket algorithm.
 *
 * @param key       Pointer to the rate limit key (e.g., IP and port).
 * @param settings  Pointer to rate limit settings (bucket size, refill rate, interval).
 * @return          0 if allowed (token consumed), -1 if rate limit exceeded.
 */
static inline int rate_limit__check_and_take(struct ratelimit_key *key, const struct ratelimit_settings *settings)
{
    struct ratelimit_value *value;
    struct ratelimit_value new_value;
    __u64 now = bpf_ktime_get_ns();
    __u64 topup;

    value = bpf_map_lookup_elem(&map_of_local_ratelimit, key);
    if (!value) {
        new_value.last_topup = now;
        new_value.tokens = settings->bucket_size;
        bpf_map_update_elem(&map_of_local_ratelimit, key, &new_value, BPF_ANY);
        return 0;
    }

    topup = (now - value->last_topup) / settings->topup_interval_ns;
    if (topup > 0) {
        value->tokens += topup * settings->tokens_per_topup;
        if (value->tokens > settings->bucket_size) {
            value->tokens = settings->bucket_size;
        }
        value->last_topup += topup * settings->topup_interval_ns;
    }

    if (value->tokens == 0) {
        return -1;
    }

    value->tokens--;
    return 0;
}

static inline int Local_rate_limit__filter__match(const Listener__Filter *filter);

static inline int
Local_rate_limit__filter_chain__match(const Listener__FilterChain *filter_chain, Listener__Filter **filter_ptr);

/**
 * Applies local rate limiting based on the filter chain and address.
 *
 * @param filter_chain Pointer to the filter chain.
 * @param addr         Pointer to the address structure.
 * @param ctx          Pointer to the context buffer.
 * @return             0 if allowed, -1 if rate limit exceeded or runtime error.
 */
static inline int
Local_rate_limit__check_and_take(const Listener__FilterChain *filter_chain, address_t *addr, const ctx_buff_t *ctx)
{
    int ret = 0;
    Listener__Filter *filter = NULL;
    Filter__LocalRateLimit *rate_limit = NULL;
    Filter__TokenBucket *token_bucket = NULL;

    ret = Local_rate_limit__filter_chain__match(filter_chain, &filter);
    if (ret) {
        BPF_LOG(INFO, FILTERCHAIN, "no local rate limit filter matched\n");
        return 0;
    }
    BPF_LOG(INFO, FILTER, "local rate limit rule matched\n");

    rate_limit = kmesh_get_ptr_val(filter->local_rate_limit);
    if (!rate_limit) {
        BPF_LOG(ERR, FILTERCHAIN, "get rate_limit failed\n");
        return -1;
    }
    token_bucket = kmesh_get_ptr_val(rate_limit->token_bucket);
    if (!token_bucket) {
        BPF_LOG(ERR, FILTERCHAIN, "get token_bucket failed\n");
        return -1;
    }

    struct ratelimit_key key = {
        .key.sk_skb.ipv4 = addr->ipv4,
        .key.sk_skb.port = addr->port,
    };

    struct ratelimit_settings settings = {
        .bucket_size = token_bucket->max_tokens,
        .tokens_per_topup = token_bucket->tokens_per_fill,
        .topup_interval_ns = token_bucket->fill_interval,
    };

    if (rate_limit__check_and_take(&key, &settings)) {
        BPF_LOG(INFO, FILTERCHAIN, "rate limit exceeded\n");
// TODO: implement rate limit exceeded action after #570 merged.
#define MARK_REJECTED(ctx)
        MARK_REJECTED(ctx);
        return -1;
    }
    BPF_LOG(INFO, FILTERCHAIN, "rate limit passed\n");
    return 0;
}

static inline int Local_rate_limit__filter__match(const Listener__Filter *filter)
{
    if (!filter) {
        BPF_LOG(ERR, FILTER, "filter is NULL\n");
        return 0;
    }

    if (filter->config_type_case != LISTENER__FILTER__CONFIG_TYPE_LOCAL_RATE_LIMIT) {
        return 0;
    }
    return 1;
}

static inline int
Local_rate_limit__filter_chain__match(const Listener__FilterChain *filter_chain, Listener__Filter **filter_ptr)
{
    void *ptrs = NULL;
    Listener__Filter *filter = NULL;

    if (!filter_ptr) {
        BPF_LOG(ERR, FILTERCHAIN, "invalid params\n");
        return -1;
    }

    if (filter_chain->n_filters == 0 || filter_chain->n_filters > KMESH_PER_FILTER_NUM) {
        BPF_LOG(ERR, FILTERCHAIN, "nfilter num(%d) invalid\n", filter_chain->n_filters);
        return -1;
    }

    ptrs = kmesh_get_ptr_val(filter_chain->filters);
    if (!ptrs) {
        BPF_LOG(ERR, FILTER, "failed to get filter ptrs\n");
        return -1;
    }

#pragma unroll
    for (unsigned int i = 0; i < KMESH_PER_FILTER_NUM; i++) {
        if (i >= filter_chain->n_filters) {
            break;
        }

        filter = (Listener__Filter *)kmesh_get_ptr_val((void *)*((__u64 *)ptrs + i));
        if (!filter) {
            continue;
        }

        if (Local_rate_limit__filter__match(filter)) {
            *filter_ptr = filter;
            return 0;
        }
    }
    return -1;
}

#endif