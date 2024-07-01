// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <sys/socket.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bpf_log.h"
#include "encoder.h"

/*
 * sk msg is used to encode metadata into the payload when the client sends
 * data to waypoint.
 *
 * The TLV format is used for encoding.
 * Currently, only the dst ip and dst port of the original link need to be
 * transferred to the waypoint.
 *
 * The current TLV format is simple. TLV structure is as follows:
 * |TLV TYPE(1byte)|TLV LENGTH(4bytes)|TLV DATA|\
 *
 * When only the dst information needs to be transferred, the information
 * added to the payload is as follows:
 * |0x01|8|[dst ip][dst port]|
 *   ===> [dst ip] 4bytes, [dst port] 2bytes, data length 6 bytes, total 11 bytes
 * |0xfe| 0|
 * payload..
 * total need add (1 + 4 + 4 + 2) + (1 + 4) = 16 bytes
 */

#define TLV_TYPE_SIZE   1
#define TLV_LENGTH_SIZE 4

#define TLV_IP4_LENGTH  4
#define TLV_IP6_LENGTH  16
#define TLV_PORT_LENGTH 2

/*
[dst_ip4]   - 4 bytes
[dst_port]  - 2 bytes
*/
#define TLV_ORG_DST_ADDR4_LENGTH (TLV_IP4_LENGTH + TLV_PORT_LENGTH)
#define TLV_ORG_DST_ADDR6_LENGTH (TLV_IP6_LENGTH + TLV_PORT_LENGTH)

/*
[TYPE]      - TLV_TYPE_SIZE byte
[length]    - TLV_LENGTH_SIZE bytes
[dst_ip4]   - TLV_IP4_LENGTH bytes
[dst_port]  - TLV_PORT_LENGTH bytes
*/
#define TLV_ORG_DST_ADDR4_SIZE (TLV_TYPE_SIZE + TLV_LENGTH_SIZE + TLV_ORG_DST_ADDR4_LENGTH)

#define TLV_ORG_DST_ADDR6_SIZE (TLV_TYPE_SIZE + TLV_LENGTH_SIZE + TLV_ORG_DST_ADDR6_LENGTH)
/*
An empty TLV block indicates the end, e.g:
[type=0xfe]
[length = 0]
*/
#define TLV_END_SIZE (TLV_TYPE_SIZE + TLV_LENGTH_SIZE)

#define FORMAT_IP_LENGTH 16
/*
tlv struct
[TYPE]      - 1 byte, define tlv block type
[length]    - 4 bytes, size of value
[value]     - 'length' bytes, payload
*/
enum TLV_TYPE {
    TLV_ORG_DST_ADDR = 0x01,
    TLV_PAYLOAD = 0xfe,
};

static inline int check_overflow(struct sk_msg_md *msg, __u8 *begin, __u32 length)
{
    if (msg->data_end < (void *)(begin + length)) {
        BPF_LOG(ERR, SENDMSG, "msg over flow\n");
        return 1;
    }
    return 0;
}

static inline int get_origin_dst(struct sk_msg_md *msg, struct ip_addr *dst_ip, __u16 *dst_port)
{
    __u64 *current_sk = (__u64 *)msg->sk;
    struct bpf_sock_tuple *dst;

    dst = bpf_map_lookup_elem(&map_of_dst_info, &current_sk);
    if (!dst)
        return -ENOENT;

    if (msg->family == AF_INET) {
        dst_ip->ip4 = dst->ipv4.daddr;
        *dst_port = dst->ipv4.dport;
    } else {
        bpf_memcpy(dst_ip->ip6, dst->ipv6.daddr, IPV6_ADDR_LEN);
        *dst_port = dst->ipv6.dport;
    }

    bpf_map_delete_elem(&map_of_dst_info, &current_sk);
    return 0;
}

static inline int alloc_dst_length(struct sk_msg_md *msg, __u32 length)
{
    int ret;
    ret = bpf_msg_push_data(msg, 0, length, 0);
    if (ret) {
        BPF_LOG(ERR, SENDMSG, "failed to alloc memory for msg, length is %d\n", length);
        return 1;
    }
    return 0;
}

#define SK_MSG_WRITE_BUF(sk_msg, offset, payload, payloadlen)                                                          \
    do {                                                                                                               \
        __u8 *begin = (__u8 *)((sk_msg)->data) + *(offset);                                                            \
        if (check_overflow((sk_msg), begin, payloadlen)) {                                                             \
            BPF_LOG(ERR, SENDMSG, "sk msg write buf overflow, off: %u, len: %u\n", *(offset), payloadlen);             \
            break;                                                                                                     \
        }                                                                                                              \
        bpf_memcpy(begin, payload, payloadlen);                                                                        \
        *(offset) += (payloadlen);                                                                                     \
    } while (0)

static inline void encode_metadata_end(struct sk_msg_md *msg, __u32 *off)
{
    __u8 type = TLV_PAYLOAD;
    __u32 size = 0;

    SK_MSG_WRITE_BUF(msg, off, &type, TLV_TYPE_SIZE);
    SK_MSG_WRITE_BUF(msg, off, &size, TLV_LENGTH_SIZE);
    return;
}

static inline void encode_metadata_org_dst_addr(struct sk_msg_md *msg, __u32 *off, bool v4)
{
    struct ip_addr dst_ip = {0};
    __u16 dst_port;
    __u8 type = TLV_ORG_DST_ADDR;
    __u32 tlv_size = (v4 ? TLV_ORG_DST_ADDR4_SIZE : TLV_ORG_DST_ADDR6_SIZE);
    __u32 addr_size = (v4 ? TLV_ORG_DST_ADDR4_LENGTH : TLV_ORG_DST_ADDR6_LENGTH);

    if (get_origin_dst(msg, &dst_ip, &dst_port))
        return;

    if (alloc_dst_length(msg, tlv_size + TLV_END_SIZE))
        return;

    BPF_LOG(DEBUG, SENDMSG, "get valid dst, do encoding...\n");

    // write T
    SK_MSG_WRITE_BUF(msg, off, &type, TLV_TYPE_SIZE);

    // write L
    addr_size = bpf_htonl(addr_size);
    SK_MSG_WRITE_BUF(msg, off, &addr_size, TLV_LENGTH_SIZE);

    // write V
    if (v4)
        SK_MSG_WRITE_BUF(msg, off, (__u8 *)&dst_ip.ip4, TLV_IP4_LENGTH);
    else
        SK_MSG_WRITE_BUF(msg, off, (__u8 *)dst_ip.ip6, TLV_IP6_LENGTH);
    SK_MSG_WRITE_BUF(msg, off, &dst_port, TLV_PORT_LENGTH);

    // write END
    encode_metadata_end(msg, off);
    return;
}

SEC("sk_msg")
int sendmsg_prog(struct sk_msg_md *msg)
{
    __u32 off = 0;
    if (msg->family != AF_INET && msg->family != AF_INET6)
        return SK_PASS;

    // encode org dst addr
    encode_metadata_org_dst_addr(msg, &off, (msg->family == AF_INET));
    return SK_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;