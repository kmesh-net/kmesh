// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

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

#include "defer_connect.h"

static struct proto *kmesh_defer_proto = NULL;
#define KMESH_DELAY_ERROR -1000

#define BPF_CGROUP_RUN_PROG_INET4_CONNECT_KMESH(sk, uaddr, t_ctx)                                                      \
    ({                                                                                                                 \
        int __ret = -1;                                                                                                \
        if (t_ctx == NULL) {                                                                                           \
            __ret = -EINVAL;                                                                                           \
        } else {                                                                                                       \
            __ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, CGROUP_INET4_CONNECT, t_ctx);                         \
        }                                                                                                              \
        __ret;                                                                                                         \
    })

static int defer_connect(struct sock *sk, struct msghdr *msg, size_t size)
{
    struct bpf_mem_ptr tmpMem = {0};
    void *kbuf = NULL;
    size_t kbuf_size;
    long timeo = 1;
    const struct iovec *iov;
    struct bpf_sock_addr_kern sock_addr;
    struct sockaddr_in uaddr;
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

    // daddr == 0 && dport == 0 are special flags meaning the circuit breaker is open
    // Should reject connection here
    if (daddr == 0 && dport == 0) {
        tcp_set_state(sk, TCP_CLOSE);
        sk->sk_route_caps = 0;
        inet_sk(sk)->inet_dport = 0;
        err = -1;
        goto out;
    }
#else
    uaddr.sin_family = AF_INET;
    uaddr.sin_addr.s_addr = daddr;
    uaddr.sin_port = dport;
    err = BPF_CGROUP_RUN_PROG_INET4_CONNECT_KMESH(sk, (struct sockaddr *)&uaddr, &tmpMem);
#endif
connect:
    err = sk->sk_prot->connect(sk, (struct sockaddr *)&uaddr, sizeof(struct sockaddr_in));
    if (unlikely(err)) {
        tcp_set_state(sk, TCP_CLOSE);
        sk->sk_route_caps = 0;
        inet_sk(sk)->inet_dport = 0;
        goto out;
    }
    inet_sk(sk)->defer_connect = 0;

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
