// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>

#define KMESH_DELAY_ERROR -1000

struct context {
    int *err;
};

SEC("raw_tracepoint.w")
int connect_ret(struct context *ctx)
{
    if (*ctx->err == KMESH_DELAY_ERROR)
        *ctx->err = 0;
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
__u32 _version SEC("version") = 1;
