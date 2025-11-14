// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

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

#define KMESH_MODULE_ULP_NAME "kmesh_defer"

static struct proto *kmesh_defer_proto = NULL;

#if KERNEL_KFUNC
#define BPF_CGROUP_RUN_PROG_INET4_CONNECT_KMESH(sk, uaddr, uaddrlen, t_ctx)                                            \
    ({                                                                                                                 \
        int __ret = -1;                                                                                                \
        if (t_ctx == NULL) {                                                                                           \
            __ret = -EINVAL;                                                                                           \
        } else {                                                                                                       \
            __ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, uaddrlen, CGROUP_INET4_CONNECT, t_ctx, NULL);         \
        }                                                                                                              \
        __ret;                                                                                                         \
    })

#define SET_DEFER_CONNECT_ON(sk)  (inet_set_bit(DEFER_CONNECT, sk))
#define SET_DEFER_CONNECT_OFF(sk) (inet_clear_bit(DEFER_CONNECT, sk))
#define IS_DEFER_CONNECT(sk)      (inet_test_bit(DEFER_CONNECT, sk))
#else
#define BPF_CGROUP_RUN_PROG_INET4_CONNECT_KMESH(sk, uaddr, uaddrlen, t_ctx)                                            \
    ({                                                                                                                 \
        int __ret = -1;                                                                                                \
        if (t_ctx == NULL) {                                                                                           \
            __ret = -EINVAL;                                                                                           \
        } else {                                                                                                       \
            __ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, CGROUP_INET4_CONNECT, t_ctx);                         \
        }                                                                                                              \
        __ret;                                                                                                         \
    })

#define SET_DEFER_CONNECT_ON(sk)  (inet_sk(sk)->defer_connect = 1)
#define SET_DEFER_CONNECT_OFF(sk) (inet_sk(sk)->defer_connect = 0)
#define IS_DEFER_CONNECT(sk)      (inet_sk(sk)->defer_connect == 1)
#endif

static int defer_connect(struct sock *sk, struct msghdr *msg, size_t size)
{
    struct bpf_mem_ptr tmpMem = {0};
    void *kbuf = NULL;
    size_t kbuf_size;
    long timeo = 1;
    const struct iovec *iov;
    struct bpf_sock_addr_kern sock_addr;
    struct sockaddr_in uaddr;
    int uaddrlen = sizeof(struct sockaddr_in);
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
#if KERNEL_VERISON6
        iov = msg->msg_iter.__iov;
        ubase = iov->iov_base;
        kbuf_size = iov->iov_len;
    } else if (iter_is_ubuf(&msg->msg_iter)) {
        ubase = msg->msg_iter.ubuf;
        kbuf_size = msg->msg_iter.count;
#else
        iov = msg->msg_iter.iov;
        ubase = iov->iov_base;
        kbuf_size = iov->iov_len;
#endif

    } else
        goto connect;

    kbuf = (void *)kmalloc(kbuf_size, GFP_KERNEL);
    if (!kbuf) {
        LOG(KERN_ERR, "kbuf kmalloc failed\n");
        return -EFAULT;
    }

    if (copy_from_user(kbuf, ubase, kbuf_size)) {
        LOG(KERN_ERR, "copy_from_user failed\n");
        err = -EFAULT;
        goto out;
    }
    tmpMem.size = kbuf_size;
    tmpMem.ptr = kbuf;

    uaddr.sin_family = AF_INET;
    uaddr.sin_addr.s_addr = daddr;
    uaddr.sin_port = dport;
    err = BPF_CGROUP_RUN_PROG_INET4_CONNECT_KMESH(sk, (struct sockaddr *)&uaddr, &uaddrlen, &tmpMem);

connect:
    err = sk->sk_prot->connect(sk, (struct sockaddr *)&uaddr, sizeof(struct sockaddr_in));
    if (unlikely(err)) {
        LOG(KERN_ERR, "connect failed:%d\n", err);
        tcp_set_state(sk, TCP_CLOSE);
        sk->sk_route_caps = 0;
        inet_sk(sk)->inet_dport = 0;
        goto out;
    }
    SET_DEFER_CONNECT_OFF(sk);

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

    if (unlikely(IS_DEFER_CONNECT(sk))) {
        lock_sock(sk);

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
    /* defer_connect is 0 when you first enter the connection.
     * When you delay link establishment from sendmsg, the value
     * of defer_connect should be 1 and the normal connect function
     * needs to be used.
     */
    if (IS_DEFER_CONNECT(sk))
        return tcp_v4_connect(sk, uaddr, addr_len);
    SET_DEFER_CONNECT_ON(sk);
    sk->sk_dport = ((struct sockaddr_in *)uaddr)->sin_port;
    sk_daddr_set(sk, ((struct sockaddr_in *)uaddr)->sin_addr.s_addr);
    sk->sk_socket->state = SS_CONNECTING;
    tcp_set_state(sk, TCP_SYN_SENT);
    return 0;
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
    .name = KMESH_MODULE_ULP_NAME,
    .owner = THIS_MODULE,
    .init = kmesh_defer_init,
};

int __init defer_conn_init(void)
{
    kmesh_defer_proto = kmalloc(sizeof(struct proto), GFP_ATOMIC);
    if (!kmesh_defer_proto) {
        LOG(KERN_ERR, "kmesh_defer_proto kmalloc failed\n");
        return -ENOMEM;
    }
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
