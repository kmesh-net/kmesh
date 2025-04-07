#include "bpf_log.h"
#include "bpf_common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_IOVEC 4
#define __MAX_CONCURRENCY   1000
#define INT_LEN                 32

// direction
enum {
    INVALID_DIRECTION = 0,
    INBOUND = 1,
    OUTBOUND = 2,
};

typedef __u64 conn_ctx_t;         // pid & tgid

struct user_msghdr {
	void *msg_name;
	int msg_namelen;
	struct iovec *msg_iov;
	__kernel_size_t msg_iovlen;
	void *msg_control;
	__kernel_size_t msg_controllen;
	unsigned int msg_flags;
};

struct sys_enter_sendmsg_args {
    unsigned long long __unused__;
    long __syscall_nr;
    int fd;
    struct user_msghdr *msg;
    unsigned int flags;
};

struct sys_connect_args_s {
    int fd;
    const struct sockaddr* addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} map_of_http_probe SEC(".maps");

struct http_probe_info {
    // For sendmsg()/recvmsg()/writev()/readv().
    __u32 type;
    struct bpf_sock_tuple tuple;
    uintptr_t iov;
    char dst_svc_name[BPF_DATA_MAX_LEN];

    // unsigned int iovlen;
    // unsigned int iovlen2;
};

static inline void construct_tuple(struct bpf_sock *sk, struct bpf_sock_tuple *tuple, __u8 direction)
{
    if (direction == OUTBOUND) {
        if (sk->family == AF_INET) {
            tuple->ipv4.saddr = sk->src_ip4;
            tuple->ipv4.daddr = sk->dst_ip4;
            tuple->ipv4.sport = sk->src_port;
            tuple->ipv4.dport = bpf_ntohs(sk->dst_port);
        }
        if (sk->family == AF_INET6) {
            bpf_memcpy(tuple->ipv6.saddr, sk->src_ip6, IPV6_ADDR_LEN);
            bpf_memcpy(tuple->ipv6.daddr, sk->dst_ip6, IPV6_ADDR_LEN);
            tuple->ipv6.sport = sk->src_port;
            tuple->ipv6.dport = bpf_ntohs(sk->dst_port);
        }
    }
    if (direction == INBOUND) {
        if (sk->family == AF_INET) {
            tuple->ipv4.daddr = sk->src_ip4;
            tuple->ipv4.saddr = sk->dst_ip4;
            tuple->ipv4.dport = sk->src_port;
            tuple->ipv4.sport = bpf_ntohs(sk->dst_port);
        }
        if (sk->family == AF_INET6) {
            bpf_memcpy(tuple->ipv6.saddr, sk->dst_ip6, IPV6_ADDR_LEN);
            bpf_memcpy(tuple->ipv6.daddr, sk->src_ip6, IPV6_ADDR_LEN);
            tuple->ipv6.dport = sk->src_port;
            tuple->ipv6.sport = bpf_ntohs(sk->dst_port);
        }
    }

    if (is_ipv4_mapped_addr(tuple->ipv6.daddr)) {
        tuple->ipv4.saddr = tuple->ipv6.saddr[3];
        tuple->ipv4.daddr = tuple->ipv6.daddr[3];
        tuple->ipv4.sport = tuple->ipv6.sport;
        tuple->ipv4.dport = tuple->ipv6.dport;
    }

    return;
}

// 1.根据pid_tgid查找map，获得sk
// 2.根据sk查找map，获得其他信息
// 3.将信息整合上报
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int sendmsg_entry(struct sys_enter_sendmsg_args *ctx) {

    struct bpf_tcp_sock *tcp_sock = NULL;
    struct sock_storage_data *storage = NULL;
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);

    struct bpf_sock *sk = bpf_map_lookup_elem(&map_of_pid_dst, &id);
    if (sk == NULL) {
        bpf_printk("bpf_map_lookup_elem map_of_pid_dst failed!\n");
        return 1;
        //BPF_LOG(ERR, TRACEPOINT, "bpf_map_lookup_elem map_of_pid_dst failed!\n");
    }

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!storage) {
        bpf_printk("sendmsg_entry bpf_sk_storage_get failed!\n");
        //BPF_LOG(ERR, PROBE, "pre_connect bpf_sk_storage_get failed\n");
        return 1;
    }

    struct http_probe_info *info = bpf_ringbuf_reserve(&map_of_http_probe, sizeof(struct http_probe_info), 0);
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return 1;
    construct_tuple(sk, &info->tuple, storage->direction);
    bpf_strncpy(storage->dst_svc_name, sizeof(storage->dst_svc_name), info->dst_svc_name);

    int fd = ctx->fd;
    struct user_msghdr *msg = ctx->msg;
    void * msg_name = BPF_CORE_READ_USER(msg, msg_name);
    struct iovec* iov = BPF_CORE_READ_USER(msg, msg_iov);
    size_t iovlen = BPF_CORE_READ_USER(msg, msg_iovlen);
    bpf_printk("sys_enter_sendmsg\n");

    if (msg_name) {
        struct sys_connect_args_s args = {0};
        args.fd = fd;
        args.addr = msg_name;
        bpf_printk("SENDMSG msg_name =%s \n", args.addr->sa_data);
    }

    info->iov = (uintptr_t)iov;

    // bpf_ringbuf_submit
    bpf_ringbuf_submit(info, 0);
    bpf_printk("SENDMSG msg_name =%s iov_len:%u\n", msg_name, iovlen);
    return 0;
}

char _license[] SEC("license") = "GPL";