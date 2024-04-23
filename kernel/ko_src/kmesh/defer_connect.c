/*
 * Copyright 2023 The Kmesh Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 * Author: liuxin
 * Create: 2022-08-24
 */

#include "../../../config/kmesh_marcos_def.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/bpf.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/udp.h>

static struct proto *kmesh_defer_proto = NULL;
#define KMESH_DELAY_ERROR -1000

static int defer_connect(struct sock *sk, struct msghdr *msg, size_t size)
{
    struct bpf_mem_ptr tmpMem = {0};
    void *kbuf = NULL;
    size_t kbuf_size;
    struct sockaddr_in addr_in;
    long timeo = 1;
    const struct iovec *iov;
    struct bpf_sock_ops_kern sock_ops;
    void __user *ubase;
    int err;
    u32 dport, daddr;
    dport = sk->sk_dport;
    daddr = sk->sk_daddr;

    if (iov_iter_is_kvec(&msg->msg_iter)) {
        iov = (struct iovec *)msg->msg_iter.kvec;
        ubase = iov->iov_base;
        kbuf_size = iov->iov_len;
    } else if (iter_is_iovec(&msg->msg_iter)) {
        iov = msg->msg_iter.iov;
        ubase = iov->iov_base;
        kbuf_size = iov->iov_len;
#if ITER_TYPE_IS_UBUF
    } else if (iter_is_ubuf(&msg->msg_iter)) {
        ubase = msg->msg_iter.ubuf;
        kbuf_size = msg->msg_iter.count;
#endif
    } else
        goto connect;

    kbuf = (void *)kmalloc(kbuf_size, GFP_KERNEL);
    if (!kbuf)
        return -EFAULT;

    if (copy_from_user(kbuf, ubase, kbuf_size)) {
        err = -EFAULT;
        goto out;
    }
    tmpMem.size = kbuf_size;
    tmpMem.ptr = kbuf;

#if OE_23_03
    tcp_call_bpf_3arg(
        sk,
        BPF_SOCK_OPS_TCP_DEFER_CONNECT_CB,
        ((u64)(&tmpMem) & U32_MAX),
        (((u64)(&tmpMem) >> 32) & U32_MAX),
        kbuf_size);
    daddr = sk->sk_daddr;
    dport = sk->sk_dport;
#else
    memset(&sock_ops, 0, offsetof(struct bpf_sock_ops_kern, temp));
    if (sk_fullsock(sk)) {
        sock_ops.is_fullsock = 1;
        sock_owned_by_me(sk);
    }
    sock_ops.sk = sk;
    sock_ops.op = BPF_SOCK_OPS_TCP_DEFER_CONNECT_CB;
    sock_ops.args[0] = ((u64)(&tmpMem) & U32_MAX);
    sock_ops.args[1] = (((u64)(&tmpMem) >> 32) & U32_MAX);

    (void)BPF_CGROUP_RUN_PROG_SOCK_OPS(&sock_ops);
    if (sock_ops.replylong[2] && sock_ops.replylong[3]) {
        daddr = sock_ops.replylong[2];
        dport = sock_ops.replylong[3];
    }
#endif
connect:
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = daddr;
    addr_in.sin_port = dport;
    err = sk->sk_prot->connect(sk, (struct sockaddr *)&addr_in, sizeof(struct sockaddr_in));
    inet_sk(sk)->bpf_defer_connect = 0;
    if (unlikely(err)) {
        tcp_set_state(sk, TCP_CLOSE);
        sk->sk_route_caps = 0;
        inet_sk(sk)->inet_dport = 0;
        goto out;
    }

    if ((((__u32)1 << sk->sk_state) & ~(__u32)(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) && !tcp_passive_fastopen(sk)) {
        sk_stream_wait_connect(sk, &timeo);
    }
out:
    kfree(kbuf);
    return err;
}

static int defer_connect_and_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
    struct socket *sock;
    int err = 0;

    if (unlikely(inet_sk(sk)->bpf_defer_connect == 1)) {
        lock_sock(sk);
        inet_sk(sk)->defer_connect = 0;

        err = defer_connect(sk, msg, size);
        if (err) {
            release_sock(sk);
            return -EAGAIN;
        }

        sock = sk->sk_socket;
        if (sock->ops->sendmsg_locked)
            err = sock->ops->sendmsg_locked(sk, msg, size);
        release_sock(sk);
    }
    return err;
}

static int defer_tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
    int ret;

    ret = defer_connect_and_sendmsg(sk, msg, size);
    if (ret)
        return ret;

    return tcp_sendmsg(sk, msg, size);
}

static int defer_tcp_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    /* Kmesh is not compatible with defer_connect, so we
     * need to check whether defer_connect is set to 1.
     * Kmesh reuses the defer_connect flag to enable the
     * epoll to be triggered normally.
     */
    if (inet_sk(sk)->defer_connect == 1)
        return -ENOTSUPP;
    /* bpf_defer_connect is 0 when you first enter the connection.
     * When you delay link establishment from sendmsg, the value
     * of bpf_defer_connect should be 1 and the normal connect function
     * needs to be used.
     */
    if (inet_sk(sk)->bpf_defer_connect)
        return tcp_v4_connect(sk, uaddr, addr_len);
    inet_sk(sk)->bpf_defer_connect = 1;
    inet_sk(sk)->defer_connect = 1;
    sk->sk_dport = ((struct sockaddr_in *)uaddr)->sin_port;
    sk_daddr_set(sk, ((struct sockaddr_in *)uaddr)->sin_addr.s_addr);
    sk->sk_socket->state = SS_CONNECTING;
    tcp_set_state(sk, TCP_SYN_SENT);
    return KMESH_DELAY_ERROR;
}

static int kmesh_build_proto(struct sock *sk)
{
    if (sk->sk_family != AF_INET)
        return 0;
    WRITE_ONCE(sk->sk_prot, kmesh_defer_proto);
    return 0;
}

static int kmesh_defer_init(struct sock *sk)
{
    kmesh_build_proto(sk);
    return 0;
}

static struct tcp_ulp_ops kmesh_defer_ulp_ops __read_mostly = {
    .name = "kmesh_defer",
    .owner = THIS_MODULE,
    .init = kmesh_defer_init,
};

int __init defer_conn_init(void)
{
    kmesh_defer_proto = kmalloc(sizeof(struct proto), GFP_ATOMIC);
    if (!kmesh_defer_proto)
        return -ENOMEM;
    *kmesh_defer_proto = tcp_prot;
    kmesh_defer_proto->connect = defer_tcp_connect;
    kmesh_defer_proto->sendmsg = defer_tcp_sendmsg;
    tcp_register_ulp(&kmesh_defer_ulp_ops);
    return 0;
}

void __exit defer_conn_exit(void)
{
    tcp_unregister_ulp(&kmesh_defer_ulp_ops);
    if (kmesh_defer_proto)
        kfree(kmesh_defer_proto);
}

MODULE_LICENSE("GPL");
