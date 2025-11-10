// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/filter.h>
#include <linux/bpfptr.h>
#include <net/tcp.h>
#include <linux/init.h>
#include <linux/string.h>
#include "kmesh_func.h"

#ifdef KERNEL_KFUNC
__diag_push();
__diag_ignore_all("-Wmissing-prototypes", "Global functions as their definitions will be in BTF");

__bpf_kfunc int bpf_km_header_strnstr_func(void *ctx, int ctx__sz, const char *key, int key__sz, const char *subptr)
{
    struct bpf_sock_addr_kern *sa_kern = ctx;
    int subptr__sz = 5;
    return bpf_km_header_strnstr_impl(ctx, key, key__sz, subptr, subptr__sz);
}

__bpf_kfunc int bpf_km_header_strncmp_func(const char *key, int key_sz, const char *target, int target_len, int opt)
{
    return bpf_km_header_strncmp_impl(key, key_sz, target, target_len, opt);
}

__bpf_kfunc int bpf_parse_header_msg_func(void *bpf_mem, int src__sz)
{
    struct bpf_mem_ptr *tmp = bpf_mem;
    struct bpf_sock_addr_kern *ctx = tmp->ptr;
    return parse_protocol_impl(ctx);
}

__bpf_kfunc int bpf_setsockopt_func(void *bpf_mem, int bpf_socket__sz, int optname, const char *optval, int optval__sz)
{
    struct bpf_mem_ptr *tmp = bpf_mem;
    struct bpf_sock_addr_kern *ctx = tmp->ptr;
    struct sock *sk = ctx->sk;

    if (sk == NULL) {
        LOG(KERN_ERR, "sk is NULL\n");
        return -1;
    }
    return tcp_setsockopt(sk, SOL_TCP, optname, KERNEL_SOCKPTR(optval), optval__sz);
}

__bpf_kfunc int bpf_getsockopt_func(void *bpf_mem, int bpf_socket__sz, int optname, char *opt, int opt__sz)
{
    struct bpf_mem_ptr *tmp = bpf_mem;
    struct bpf_sock_addr_kern *ctx = tmp->ptr;
    struct sock *sk = ctx->sk;

    struct inet_connection_sock *icsk = inet_csk(sk);
    int len;

    sockptr_t optval = KERNEL_SOCKPTR(opt);
    sockptr_t optlen = KERNEL_SOCKPTR(&opt__sz);

    if (copy_from_sockptr(&len, optlen, sizeof(int)))
        return -EFAULT;

    if (len < 0)
        return -EINVAL;

    len = min_t(unsigned int, len, TCP_ULP_NAME_MAX);
    if (!icsk->icsk_ulp_ops) {
        len = 0;
        if (copy_to_sockptr(optlen, &len, sizeof(int)))
            return -EFAULT;
        return -EINVAL;
    }
    if (copy_to_sockptr(optlen, &len, sizeof(int)))
        return -EFAULT;
    if (copy_to_sockptr(optval, icsk->icsk_ulp_ops->name, len))
        return -EFAULT;
    return 0;
}

__diag_pop();

BTF_SET8_START(bpf_kmesh_kfunc)
BTF_ID_FLAGS(func, bpf_km_header_strnstr_func)
BTF_ID_FLAGS(func, bpf_km_header_strncmp_func)
BTF_ID_FLAGS(func, bpf_parse_header_msg_func)
BTF_ID_FLAGS(func, bpf_setsockopt_func)
BTF_ID_FLAGS(func, bpf_getsockopt_func)
BTF_SET8_END(bpf_kmesh_kfunc)

static const struct btf_kfunc_id_set bpf_kmesh_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kmesh_kfunc,
};

int __init kmesh_func_init(void)
{
    int ret;
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &bpf_kmesh_kfunc_set);
    if (ret < 0) {
        pr_err("ret is not zero:%d\n", ret);
        return ret;
    }
    return 0;
}

void __exit kmesh_func_exit(void)
{
    return;
}

#else
typedef int (*bpf_parse_protocol_func)(struct bpf_sock_addr_kern *ctx);
extern bpf_parse_protocol_func parse_protocol_func;

typedef int (*bpf_km_header_strnstr_func)(
    struct bpf_sock_addr_kern *ctx, const char *key, int key_sz, const char *subptr, int subptr_sz);
extern bpf_km_header_strnstr_func km_header_strnstr_func;

typedef int (*bpf_km_header_strncmp_func)(const char *key, int key_sz, const char *target, int target_sz, int opt);
extern bpf_km_header_strncmp_func km_header_strncmp_func;

int __init kmesh_func_init(void)
{
    parse_protocol_func = parse_protocol_impl;
    km_header_strnstr_func = bpf_km_header_strnstr_impl;
    km_header_strncmp_func = bpf_km_header_strncmp_impl;
    return 0;
}

void __exit kmesh_func_exit(void)
{
    parse_protocol_func = NULL;
    km_header_strnstr_func = NULL;
    km_header_strncmp_func = NULL;
}

#endif
MODULE_LICENSE("Dual BSD/GPL");
