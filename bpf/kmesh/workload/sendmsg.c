/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/bpf.h>
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

#define TLV_DST_LENGTH 6
#define TLV_DST_SIZE   11
#define TLV_END_SIZE   5

#define FORMAT_IP_LENGTH 16

enum TLV_TYPE {
    TLV_DST_INFO = 0x01,
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

static inline int _encode_tlv_type(struct sk_msg_md *msg, enum TLV_TYPE type, __u32 off)
{
    __u8 *begin = (__u8 *)(msg->data) + off;
    if (check_overflow(msg, begin, 1))
        return off;
    *begin = (__u8)type;

    return off + TLV_TYPE_SIZE; // cost 1 byte
}

static inline int _encode_tlv_length(struct sk_msg_md *msg, __u32 length, __u32 off)
{
    __u32 *begin = (__u32 *)((__u8 *)(msg->data) + off);
    if (check_overflow(msg, (__u8 *)begin, 4))
        return off;
    *begin = bpf_htonl(length);
    return off + TLV_LENGTH_SIZE; // cost 4 byte
}

static inline int encode_metadata_end(struct sk_msg_md *msg, __u32 off)
{
    off = _encode_tlv_type(msg, TLV_PAYLOAD, off);
    off = _encode_tlv_length(msg, 0, off);
    return off;
}

static inline int get_origin_dst(struct sk_msg_md *msg, __u32 *dst_ip, __u16 *dst_port)
{
    __u32 *current_sk = (__u32 *)msg->sk;
    struct bpf_sock_tuple *dst;

    dst = bpf_map_lookup_elem(&map_of_dst_info, &current_sk);
    if (!dst)
        return -ENOENT;
    *dst_ip = dst->ipv4.daddr;
    *dst_port = dst->ipv4.dport;
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

static inline void encode_metadata_dst(struct sk_msg_md *msg, __u32 off)
{
    __u32 dst_ip;
    __u16 dst_port;
    __u32 *msg_dst_ip_loc;
    __u16 *msg_dst_port_loc;

    if (get_origin_dst(msg, &dst_ip, &dst_port))
        return;

    if (alloc_dst_length(msg, TLV_DST_SIZE + TLV_END_SIZE))
        return;

    BPF_LOG(DEBUG, SENDMSG, "get valid dst, do encoding...\n");

    off = _encode_tlv_type(msg, TLV_DST_INFO, off);
    off = _encode_tlv_length(msg, TLV_DST_LENGTH, off);

    msg_dst_ip_loc = (__u32 *)((__u8 *)msg->data + off);
    if (check_overflow(msg, (__u8 *)msg_dst_ip_loc, 4))
        return;
    *msg_dst_ip_loc = dst_ip;
    off += 4;

    msg_dst_port_loc = (__u16 *)((__u8 *)msg->data + off);
    if (check_overflow(msg, (__u8 *)msg_dst_port_loc, 2))
        return;
    *msg_dst_port_loc = dst_port;
    off += 2;

    encode_metadata_end(msg, off);
}

static inline void encode_metadata(struct sk_msg_md *msg, enum TLV_TYPE type, __u32 off)
{
    switch (type) {
    case TLV_DST_INFO: {
        encode_metadata_dst(msg, off);
        break;
    }
    default:
        break;
    }
}

SEC("sk_msg")
int sendmsg(struct sk_msg_md *msg)
{
    encode_metadata(msg, TLV_DST_INFO, 0);
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;