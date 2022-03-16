/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: 355931
 * Create: 2022-1-12
 */
#ifndef _XDP_H_
#define _XDP_H_

#include "common.h"
#include "tuple.h"
#include "listener.h"
#include "bpf_log.h"
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define XDP_FURTHER_PROCESSING -1
#define __CTX_OFF_MAX			0xff

bpf_map_t SEC("maps") map_of_tuple_ct = {
        .type			= BPF_MAP_TYPE_HASH,
        .key_size		= sizeof(tuple_t),
        .value_size		= sizeof(address_t),
        .max_entries	= MAP_SIZE_OF_ENDPOINT,
        .map_flags		= 0,
};

static inline
address_t* map_lookup_tuple_ct(const tuple_t* tuple)
{
    //return bpf_map_lookup_elem(&map_of_tuple_ct, tuple);
    return kmesh_map_lookup_elem(&map_of_tuple_ct, tuple);
}

static inline
int map_update_tuple_ct(const tuple_t* tuple, address_t* target)
{
    //return bpf_map_update_elem(&map_of_tuple_ct, tuple, target, BPF_ANY);
    return kmesh_map_update_elem(&map_of_tuple_ct, tuple, target);
}

static inline
int map_delete_tuple_ct(const tuple_t* tuple)
{
    //return bpf_map_delete_elem(&map_of_tuple_ct, tuple);
    return kmesh_map_delete_elem(&map_of_tuple_ct, tuple);
}

static inline __sum16 csum_fold(__wsum csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__sum16)~csum;
}


static inline __wsum csum_unfold(__sum16 csum)
{
    return (__wsum)csum;
}

static inline __wsum csum_add(__wsum csum, __wsum addend)
{
    csum += addend;
    return csum + (csum < addend);
}

static inline bpf_unused void
__csum_replace_by_diff(__sum16 *sum, __wsum diff)
{
    *sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
}

static inline bpf_unused void
__csum_replace_by_4(__sum16 *sum, __wsum from, __wsum to)
{
    __csum_replace_by_diff(sum, csum_add(~from, to));
}

static bpf_unused inline
// todo Refer to open source code and need to be rectified
int xdp_l3_csum_replace(const struct xdp_md *ctx, __u64 off, const __u32 from,
                        __u32 to,
                        __u32 flags)
{
    __u32 size = flags & BPF_F_HDR_FIELD_MASK;
    __sum16 *sum;
    int ret;

    if (flags & ~(BPF_F_HDR_FIELD_MASK))
        return -EINVAL;
    if (size != 0 && size != 2)
        return -EINVAL;
    asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
                 "r2 = *(u32 *)(%[ctx] +4)\n\t"
                 "%[off] &= %[offmax]\n\t"
                 "r1 += %[off]\n\t"
                 "%[sum] = r1\n\t"
                 "r1 += 2\n\t"
                 "if r1 > r2 goto +2\n\t"
                 "%[ret] = 0\n\t"
                 "goto +1\n\t"
                 "%[ret] = %[errno]\n\t"
    : [ret]"=r"(ret), [sum]"=r"(sum)
    : [ctx]"r"(ctx), [off]"r"(off),
    [offmax]"i"(__CTX_OFF_MAX), [errno]"i"(-EINVAL)
    : "r1", "r2");
    if (!ret)
        from ? __csum_replace_by_4(sum, from, to) :
        __csum_replace_by_diff(sum, to);
    BPF_LOG(DEBUG, KMESH, "xdp_l3_csum_replace ret is %u\n", ret);
    return ret;
}


static inline bpf_unused int
// todo Refer to open source code and need to be rectified
xdp_l4_csum_replace(const struct xdp_md *ctx, __u64 off, __u32 from, __u32 to,
                    __u32 flags)
{
    bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;
    __u32 size = flags & BPF_F_HDR_FIELD_MASK;
    __sum16 *sum;
    int ret;

    if (flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_PSEUDO_HDR |
                  BPF_F_HDR_FIELD_MASK))
        return -EINVAL;
    if (size != 0 && size != 2)
        return -EINVAL;
    asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
                 "r2 = *(u32 *)(%[ctx] +4)\n\t"
                 "%[off] &= %[offmax]\n\t"
                 "r1 += %[off]\n\t"
                 "%[sum] = r1\n\t"
                 "r1 += 2\n\t"
                 "if r1 > r2 goto +2\n\t"
                 "%[ret] = 0\n\t"
                 "goto +1\n\t"
                 "%[ret] = %[errno]\n\t"
    : [ret]"=r"(ret), [sum]"=r"(sum)
    : [ctx]"r"(ctx), [off]"r"(off),
    [offmax]"i"(__CTX_OFF_MAX), [errno]"i"(-EINVAL)
    : "r1", "r2");
    if (!ret) {
        if (is_mmzero && !*sum)
            return 0;
        from ? __csum_replace_by_4(sum, from, to) :
        __csum_replace_by_diff(sum, to);
        if (is_mmzero && !*sum)
            *sum = (__sum16)0xffff;
    }
    BPF_LOG(DEBUG, KMESH, "xdp_l4_csum_replace ret is %u\n", ret);
    return ret;
}


static inline
int xdp_l3_dnat(void* data, void* data_end, __u32 daddr) {
    struct iphdr* iph;
    iph = data + sizeof(struct ethhdr);
    if ((void*) (iph + 1) > data_end) {
        BPF_LOG(ERR, KMESH, "xdp_l3_dnat failed\n");
        return XDP_ABORTED;
    }

    iph->daddr = daddr;
    return XDP_PASS;
}

static inline
int xdp_l4_dnat(void * data, void * data_end, __u32 off_set, __u32 dport) {
    struct tcphdr * tcp;
    tcp = data + off_set;
    if ((void*)(tcp + 1) > data_end) {
        BPF_LOG(ERR, KMESH, "xdp_l3_dnat failed\n");
        return XDP_ABORTED;
    }
    tcp->dest = dport;
    return XDP_PASS;
}


static inline
int parse_xdp_address(struct xdp_md* xdp_ctx,
                      bool is_ipv6,
                      address_t* src_addr,
                      address_t* dst_addr ) {

    struct tcphdr* tcph;
    void* data = (void*)(unsigned long)xdp_ctx->data;
    void* data_end = (void*)(unsigned long)xdp_ctx->data_end;
    struct iphdr* iph = data + sizeof (struct ethhdr);
    if (is_ipv6) {
        return XDP_PASS;
    }
    if ((void*)(iph + 1) > data_end) {
        return XDP_ABORTED;
    }
    if (iph->protocol != IPPROTO_TCP) {
        BPF_LOG(DEBUG, KMESH, "parse_xdp_address iph->protocol:%u, iph->src:%u\n", iph->protocol,iph->saddr);
        return XDP_PASS;
    }

    tcph = (struct tcphdr *)(iph + 1);
    if ((void*)(tcph + 1) > data_end) {
        return XDP_ABORTED;
    }
    if (dst_addr) {
        dst_addr->ipv4 = iph->daddr;
        dst_addr->port = tcph->dest;
    }

    if (src_addr) {
        src_addr->protocol = iph->protocol;
        src_addr->ipv4 = iph->saddr;
        src_addr->port = tcph->source;
    }

    return XDP_FURTHER_PROCESSING;
}


static inline
int xdp_dnat(struct xdp_md* xdp_ctx,
             address_t* src_address,
             address_t* origin_dst,
             address_t* backend,
             bool add_tc) {
    void* data;
    void* data_end;
    __u32 l3_off;
    __u32 l4_off;
    __u32 sum_diff;
    BPF_LOG(DEBUG, KMESH, "xdp_nat,src_ip = %u,src_port=%u,proto=%u\n",
            src_address->ipv4,
            src_address->port,
            src_address->protocol);

    BPF_LOG(DEBUG, KMESH, "xdp_nat, origin dst_ip = %u, dst_port=%u\n",
            origin_dst->ipv4,
            origin_dst->port);

    BPF_LOG(DEBUG, KMESH, "xdp_nat,backend_ip=%u,backend_port=%u\n",
            backend->ipv4,
            backend->port);


    data = (void*)(long)xdp_ctx->data;
    data_end = (void*)(long)xdp_ctx->data_end;
    l3_off = sizeof(struct ethhdr);
    l4_off = l3_off + sizeof(struct iphdr);

    struct iphdr *iph = data + sizeof(struct ethhdr);
    struct tcphdr *tcp = data + l4_off;
    if ((void*) (iph + 1) > data_end) {
        return XDP_ABORTED;
    }
    if ((void*) (tcp + 1) > data_end) {
        return XDP_ABORTED;
    }

    if (XDP_ABORTED == xdp_l3_dnat(data, data_end, backend->ipv4)) {
        return XDP_ABORTED;
    }

    sum_diff = bpf_csum_diff(&origin_dst->ipv4, 4, &backend->ipv4, 4, 0);
    if (xdp_l3_csum_replace(xdp_ctx, l3_off + offsetof(struct iphdr, check),
                            0, sum_diff, 0) < 0)
        return -1;

    if (xdp_l4_csum_replace(xdp_ctx, l4_off + offsetof(struct tcphdr, check), 0, sum_diff,
                        BPF_F_PSEUDO_HDR) < 0)
        return -1;

    if (XDP_ABORTED == xdp_l4_dnat(data, data_end, l4_off, backend->port)){
        return XDP_ABORTED;
    }
    if (xdp_l4_csum_replace(xdp_ctx, l4_off + offsetof(struct tcphdr, check),
                            (__be16)origin_dst->port,(__be16) backend->port, sizeof(__be16)) < 0)
        return -1;

    if (add_tc) {
        DECLARE_TUPLE(src_address, origin_dst, tuple)
        tuple.flags = TUPLE_FLAGS_INGRESS;
        if(map_update_tuple_ct(&tuple, backend) < 0) {
            return -1;
        }
        // insert rev nat record
        DECLARE_TUPLE(backend, src_address, rev_tuple)
        rev_tuple.flags = TUPLE_FLAGS_EGRESS;
        rev_tuple.protocol = src_address->protocol;
        if(map_update_tuple_ct(&rev_tuple, origin_dst) < 0) {
            map_delete_tuple_ct(&tuple);
            return -1;
        }
    }
    return XDP_PASS;
}

#endif

