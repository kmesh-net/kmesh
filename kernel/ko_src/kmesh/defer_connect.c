#define pr_fmt(fmt) "Kmesh-defer-conn: " fmt

#include <linux/types.h>
#include <linux/net.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <linux/net.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/udp.h>

#define DEFER_CONNECT 2

static int copy_msg_from_user(struct msghdr *msg, void **to, unsigned int *len)
{
	void *kbuf = NULL;
	const struct iovec *iov;

	if (!to || !len)
		return -1;

	if (msg->msg_iter.type & ITER_KVEC)
		iov = (struct iovec *)msg->msg_iter.kvec;
	else
		iov = msg->msg_iter.iov;

	kbuf = (void *)kmalloc(iov->iov_len, GFP_KERNEL);
	if (kbuf == NULL)
		return -1;

	if (copy_from_user(kbuf, iov->iov_base, iov->iov_len))
		return -EFAULT;

	*to = kbuf;
	*len = iov->iov_len;
	return 0;
}

static void __user * kmalloc_user_memory(unsigned long size)
{
	return (void __user *)(current->mm->start_stack - 131072UL);
}

static inline int defer_msg_build(struct msghdr *orgMsg,
					   void *buf, __u32 len,
					   void __user *userBuf)
{
	/* copy kernel buf to user buf */
	int err;

	if (!userBuf)
		return -1;

	if (copy_to_user(userBuf, buf, len))
		return -EFAULT;

	/* build defer msg */
	err = import_single_range(WRITE, userBuf, len, orgMsg->msg_iter.iov, &orgMsg->msg_iter);
	return err;
}

static int defer_connect(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct bpf_mem_ptr tmpMem = {0};
	struct sockaddr_in addr_in;
	void __user *userBuf;
	long timeo;
	int err;

        err = copy_msg_from_user(msg, &(tmpMem.ptr), &(tmpMem.size));
	if (err)
		return err;

        tcp_call_bpf_3arg(sk, BPF_SOCK_OPS_TCP_DEFER_CONNECT_CB,
                          ((u64)(&tmpMem) & 0xffffffff),
                          (((u64)(&tmpMem) >> 32) & 0xffffffff), tmpMem.size);

	addr_in.sin_family = AF_INET;
	addr_in.sin_port = sk->sk_dport;
	addr_in.sin_addr.s_addr = sk->sk_daddr;
	sk->sk_prot->connect(sk, (struct sockaddr *)&addr_in,
			     sizeof(struct sockaddr_in));

        inet_sk(sk)->bpf_defer_connect = 0;

        userBuf = kmalloc_user_memory(tmpMem.size);
        err = defer_msg_build(msg, tmpMem.ptr,
				  tmpMem.size, userBuf);
        kfree(tmpMem.ptr);

        if (unlikely(err)) {
	    printk(KERN_CRIT "[tcp_sendmsg]import_single_range failed:%d\n", err);
            tcp_set_state(sk, TCP_CLOSE);
            sk->sk_route_caps = 0;
            inet_sk(sk)->inet_dport = 0;
	    return err;
        }

	timeo = 1;
	if (((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		&& !tcp_passive_fastopen(sk)) {
		sk_stream_wait_connect(sk, &timeo);
	}

	return 0;
}

static int defer_connect_and_sendmsg(struct sock *sk, struct msghdr *msg,
					    size_t size)
{
	struct socket *sock;
	int err = 0;

	if (unlikely(inet_sk(sk)->bpf_defer_connect == 1)) {
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

static int defer_inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	int ret;

	if (unlikely(inet_send_prepare(sk)))
		return -EAGAIN;

	ret = defer_connect_and_sendmsg(sk, msg, size);
	if (ret)
		return ret;

	return INDIRECT_CALL_2(sk->sk_prot->sendmsg, tcp_sendmsg, udp_sendmsg,
			       sk, msg, size);
}

static long inet_wait_for_connect(struct sock *sk, long timeo, int writebias)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	add_wait_queue(sk_sleep(sk), &wait);
	sk->sk_write_pending += writebias;

	/* Basic assumption: if someone sets sk->sk_err, he _must_
	 * change state of the socket from TCP_SYN_*.
	 * Connect() does not allow to get error notifications
	 * without closing the socket.
	 */
	while ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		release_sock(sk);
		timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);
		lock_sock(sk);
		if (signal_pending(current) || !timeo)
			break;
	}
	remove_wait_queue(sk_sleep(sk), &wait);
	sk->sk_write_pending -= writebias;
	return timeo;
}

static int __defer_inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			  int addr_len, int flags, int is_sendmsg)
{
	struct sock *sk = sock->sk;
	int err;
	long timeo;

	/*
	 * uaddr can be NULL and addr_len can be 0 if:
	 * sk is a TCP fastopen active socket and
	 * TCP_FASTOPEN_CONNECT sockopt is set and
	 * we already have a valid cookie for this socket.
	 * In this case, user can call write() after connect().
	 * write() will invoke tcp_sendmsg_fastopen() which calls
	 * __inet_stream_connect().
	 */
	if (uaddr) {
		if (addr_len < sizeof(uaddr->sa_family))
			return -EINVAL;

		if (uaddr->sa_family == AF_UNSPEC) {
			err = sk->sk_prot->disconnect(sk, flags);
			sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
			goto out;
		}
	}

	switch (sock->state) {
	default:
		err = -EINVAL;
		goto out;
	case SS_CONNECTED:
		err = -EISCONN;
		goto out;
	case SS_CONNECTING:
		if (inet_sk(sk)->defer_connect || inet_sk(sk)->bpf_defer_connect)
			err = is_sendmsg ? -EINPROGRESS : -EISCONN;
		else
			err = -EALREADY;
		/* Fall out of switch with err, set for this state */
		break;
	case SS_UNCONNECTED:
		err = -EISCONN;
		if (sk->sk_state != TCP_CLOSE)
			goto out;

		if (BPF_CGROUP_PRE_CONNECT_ENABLED(sk)) {
			err = sk->sk_prot->pre_connect(sk, uaddr, addr_len);
			if (err == DEFER_CONNECT) {
				inet_sk(sk)->bpf_defer_connect = 1;
				err = 0;
				sk->sk_dport = ((struct sockaddr_in *)uaddr)->sin_port;
				sk_daddr_set(sk, ((struct sockaddr_in *)uaddr)->sin_addr.s_addr);
				sock->state = SS_CONNECTING;
				tcp_set_state(sk, TCP_SYN_SENT);
				goto out;
			}
			if (err)
				goto out;
		}

		err = sk->sk_prot->connect(sk, uaddr, addr_len);
		if (err < 0)
			goto out;

		sock->state = SS_CONNECTING;
		if (!err && inet_sk(sk)->defer_connect) {
			goto out;
		}

		/* Just entered SS_CONNECTING state; the only
		 * difference is that return value in non-blocking
		 * case is EINPROGRESS, rather than EALREADY.
		 */
		err = -EINPROGRESS;
		break;
	}

	timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);

	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		int writebias = (sk->sk_protocol == IPPROTO_TCP) &&
				tcp_sk(sk)->fastopen_req &&
				tcp_sk(sk)->fastopen_req->data ? 1 : 0;

		/* Error code is set above */
		if (!timeo || !inet_wait_for_connect(sk, timeo, writebias))
			goto out;

		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;
	}

	/* Connection was closed by RST, timeout, ICMP error
	 * or another process disconnected us.
	 */
	if (sk->sk_state == TCP_CLOSE)
		goto sock_error;

	/* sk->sk_err may be not zero now, if RECVERR was ordered by user
	 * and error was received after socket entered established state.
	 * Hence, it is handled normally after connect() return successfully.
	 */

	sock->state = SS_CONNECTED;
	err = 0;
out:
	return err;

sock_error:
	err = sock_error(sk) ? : -ECONNABORTED;
	sock->state = SS_UNCONNECTED;
	if (sk->sk_prot->disconnect(sk, flags))
		sock->state = SS_DISCONNECTING;
	goto out;
}

static int defer_inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
		  int addr_len, int flags)
{
	int err;

	lock_sock(sock->sk);
	err = __defer_inet_stream_connect(sock, uaddr, addr_len, flags, 0);
	release_sock(sock->sk);
	return err;
}

static struct proto_ops defer_inet_stream_ops;

static struct inet_protosw defer_inetsw = {
	.type =       SOCK_STREAM,
	.protocol =   IPPROTO_TCP,
	.prot =       &tcp_prot,
	.ops =        &defer_inet_stream_ops,
	.flags =      INET_PROTOSW_PERMANENT_OVERRIDE |
		      INET_PROTOSW_ICSK,
};

int __init defer_conn_init(void)
{
	defer_inet_stream_ops = inet_stream_ops;
	defer_inet_stream_ops.owner = THIS_MODULE;
	defer_inet_stream_ops.sendmsg = defer_inet_sendmsg;
	defer_inet_stream_ops.connect = defer_inet_stream_connect;

	inet_register_protosw(&defer_inetsw);

	return 0;
}

void __exit defer_conn_exit(void)
{
	inet_unregister_protosw(&defer_inetsw);
}
