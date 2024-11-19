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
            __u64 netns;  /* Network namespace. */
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
    __uint(max_entries, MAP_SIZE_OF_LISTENER);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} kmesh_ratelimit SEC(".maps");

struct ratelimit_settings {
    __u64 max_tokens;      /* Maximum capacity of the token bucket */
    __u64 tokens_per_fill; /* Number of tokens added per refill */
    __u64 fill_interval;   /* Interval between token refills (nanoseconds) */
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
    __u64 topup_time;
    __u64 delta;

    value = bpf_map_lookup_elem(&kmesh_ratelimit, key);
    if (!value) {
        new_value.last_topup = now;
        new_value.tokens = settings->max_tokens;
        bpf_map_update_elem(&kmesh_ratelimit, key, &new_value, BPF_NOEXIST);
        value = bpf_map_lookup_elem(&kmesh_ratelimit, key);
        if (!value)
            return 0;
    }

    topup = (now - value->last_topup) / settings->fill_interval;
    if (topup > 0) {
        topup_time = value->last_topup + topup * settings->fill_interval;
        if (__sync_bool_compare_and_swap(&value->last_topup, value->last_topup, topup_time)) {
            delta = topup * settings->tokens_per_fill;
            if (value->tokens + delta > settings->max_tokens) {
                delta = settings->max_tokens - value->tokens;
            }
            __sync_fetch_and_add(&value->tokens, delta);
        }
    }

    if (value->tokens == 0) {
        return -1;
    }

    __sync_fetch_and_add(&value->tokens, -1);
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
Local_rate_limit__check_and_take(const Listener__FilterChain *filter_chain, address_t *addr, ctx_buff_t *ctx)
{
    int ret = 0;
    Listener__Filter *filter = NULL;
    Filter__LocalRateLimit *rate_limit = NULL;
    Filter__TokenBucket *token_bucket = NULL;

    ret = Local_rate_limit__filter_chain__match(filter_chain, &filter);
    if (ret) {
        BPF_LOG(DEBUG, FILTERCHAIN, "no local rate limit filter matched\n");
        return 0;
    }
    BPF_LOG(INFO, FILTER, "local rate limit rule matched\n");

    rate_limit = KMESH_GET_PTR_VAL(filter->local_rate_limit, Filter__LocalRateLimit);
    if (!rate_limit) {
        BPF_LOG(ERR, FILTERCHAIN, "get rate_limit failed\n");
        return -1;
    }
    token_bucket = KMESH_GET_PTR_VAL(rate_limit->token_bucket, Filter__TokenBucket);
    if (!token_bucket) {
        BPF_LOG(ERR, FILTERCHAIN, "get token_bucket failed\n");
        return -1;
    }

    struct ratelimit_key key = {0};
    key.key.sk_skb.ipv4 = addr->ipv4;
    key.key.sk_skb.port = addr->port;
    key.key.sk_skb.netns = bpf_get_netns_cookie((void *)ctx);

    struct ratelimit_settings settings = {
        .max_tokens = token_bucket->max_tokens,
        .tokens_per_fill = token_bucket->tokens_per_fill,
        .fill_interval = token_bucket->fill_interval,
    };

    if (rate_limit__check_and_take(&key, &settings)) {
        BPF_LOG(INFO, FILTERCHAIN, "rate limit exceeded\n");
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

    ptrs = KMESH_GET_PTR_VAL(filter_chain->filters, void *);
    if (!ptrs) {
        BPF_LOG(ERR, FILTER, "failed to get filter ptrs\n");
        return -1;
    }

#pragma unroll
    for (unsigned int i = 0; i < KMESH_PER_FILTER_NUM; i++) {
        if (i >= filter_chain->n_filters) {
            break;
        }

        filter = (Listener__Filter *)KMESH_GET_PTR_VAL((void *)*((__u64 *)ptrs + i), Listener__Filter);
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