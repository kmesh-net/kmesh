/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#include "../../config/kmesh_marcos_def.h"
#include <linux/in.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "map_config.h"

#include "errno.h"

struct bpf_mem_ptr {
    void *ptr;
    __u32 size;
};

#define KMESH_MODULE_ULP_NAME "kmesh_defer"

extern int bpf_parse_header_msg_func(void *src, int src__sz) __ksym;
extern int bpf_km_header_strnstr_func(void *ctx, int ctx__sz, const char *key, int key__sz, const char *subptr) __ksym;
extern int bpf_km_header_strncmp_func(const char *key, int key__sz, const char *target, int target__sz, int opt) __ksym;
extern int bpf_setsockopt_func(void *bpf_mem, int bpf_mem__sz, int optname, const char *optval, int optval__sz) __ksym;
extern int bpf_getsockopt_func(void *bpf_mem, int bpf_mem__sz, int optname, char *optval, int optval__sz) __ksym;

#define bpf_km_header_strncmp bpf_km_header_strncmp_func

static int bpf_km_header_strnstr(void *ctx, const char *key, int key__sz, const char *subptr, int subptr__sz)
{
    struct bpf_mem_ptr msg_tmp = {.ptr = ctx, .size = sizeof(struct bpf_sock_addr)};
    return bpf_km_header_strnstr_func(&msg_tmp, sizeof(struct bpf_mem_ptr), key, key__sz, subptr);
}

static int bpf_parse_header_msg(struct bpf_sock_addr *ctx)
{
    struct bpf_mem_ptr msg_tmp = {.ptr = ctx, .size = sizeof(struct bpf_sock_addr)};
    return bpf_parse_header_msg_func(&msg_tmp, sizeof(struct bpf_mem_ptr));
}

// Due to the limitation of bpf verifier, optval and optval__sz are required to correspond.
// The strnlen function cannot be used here, so the string is redefined.
static int bpf_km_setsockopt(struct bpf_sock_addr *ctx, int level, int optname, const char *optval, int optval__sz)
{
    const char kmesh_module_ulp_name[] = KMESH_MODULE_ULP_NAME;
    if (level != IPPROTO_TCP || optval__sz != sizeof(kmesh_module_ulp_name))
        return -1;

    struct bpf_mem_ptr msg_tmp = {.ptr = ctx, .size = sizeof(struct bpf_sock_addr)};
    return bpf_setsockopt_func(
        &msg_tmp, sizeof(struct bpf_mem_ptr), optname, (void *)kmesh_module_ulp_name, sizeof(kmesh_module_ulp_name));
}

static int bpf_km_getsockopt(struct bpf_sock_addr *ctx, int level, int optname, char *optval, int optval__sz)
{
    if (level != IPPROTO_TCP) {
        return -1;
    }
    struct bpf_mem_ptr msg_tmp = {.ptr = ctx, .size = sizeof(struct bpf_sock_addr)};
    return bpf_getsockopt_func(&msg_tmp, sizeof(struct bpf_mem_ptr), optname, (void *)optval, optval__sz);
}
