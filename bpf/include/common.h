/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef _COMMON_H_
#define _COMMON_H_

#include "../../config/kmesh_marcos_def.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "map_config.h"

#include "errno.h"

#if ENHANCED_KERNEL
#include <bpf_helper_defs_ext.h>
#endif

#define bpf_unused __attribute__((__unused__))

#define BPF_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define BPF_MIN(x, y) (((x) < (y)) ? (x) : (y))

#ifndef bpf_memset
#define bpf_memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif

#ifndef bpf_memcpy
#define bpf_memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef __stringify
#define __stringify(X) #X
#endif
#define SEC_TAIL(ID, KEY) SEC(__stringify(ID) "/" __stringify(KEY))

struct ip_addr {
    union {
        __u32 ip4;
        __u32 ip6[4];
    };
};
#define IPV6_ADDR_LEN 16

/*
eBPF verifier verifies the eBPF PROG, including the read and write permissions of the CTX parameters. In the V4 and V6
scenarios, the governance logic is similar except for the address information. However, the eBPF verifier strictly
checks the read and write operations of the ctx members. For example, v6-related variables cannot be read or written in
the v4 context. Therefore, to reuse the governance logic, kmesh_context defined to cache the input and output
information related to the address.
*/
struct kmesh_context {
    // input
    struct bpf_sock_addr *ctx;
    struct ip_addr orig_dst_addr;

    // output
    struct ip_addr dnat_ip;
    __u32 dnat_port;
    bool via_waypoint;
};

struct kmesh_config {
    __u32 bpf_log_level;
    __u32 node_ip[4];
    __u32 pod_gateway[4];
    __u32 authz_offload;
    __u32 enable_monitoring;
};

typedef struct {
    char *data;
} bytes;

static inline void *kmesh_map_lookup_elem(void *map, const void *key)
{
    return bpf_map_lookup_elem(map, key);
}

static inline int kmesh_map_delete_elem(void *map, const void *key)
{
    return (int)bpf_map_delete_elem(map, key);
}

static inline int kmesh_map_update_elem(void *map, const void *key, const void *value)
{
    // TODO: Duplicate element, status update
    return (int)bpf_map_update_elem(map, key, value, BPF_ANY);
}

static inline bool is_ipv4_mapped_addr(__u32 ip6[4])
{
    return ip6[0] == 0 && ip6[1] == 0 && ip6[2] == 0xFFFF0000;
}

#define V4_MAPPED_REVERSE(v4_mapped)                                                                                   \
    do {                                                                                                               \
        (v4_mapped)[0] = (v4_mapped)[3];                                                                               \
        (v4_mapped)[1] = 0;                                                                                            \
        (v4_mapped)[2] = 0;                                                                                            \
        (v4_mapped)[3] = 0;                                                                                            \
    } while (0)

#define V4_MAPPED_TO_V6(ipv4, ipv6)                                                                                    \
    do {                                                                                                               \
        (ipv6)[3] = (ipv4);                                                                                            \
        (ipv6)[2] = 0xFFFF0000;                                                                                        \
        (ipv6)[1] = 0;                                                                                                 \
        (ipv6)[0] = 0;                                                                                                 \
    } while (0)

#define IP6_COPY(dst, src)                                                                                             \
    do {                                                                                                               \
        (dst)[0] = (src)[0];                                                                                           \
        (dst)[1] = (src)[1];                                                                                           \
        (dst)[2] = (src)[2];                                                                                           \
        (dst)[3] = (src)[3];                                                                                           \
    } while (0)

#if OE_23_03
#define bpf__strncmp                  bpf_strncmp
#define GET_SKOPS_REMOTE_PORT(sk_ops) (__u16)((sk_ops)->remote_port)
#else
#define GET_SKOPS_REMOTE_PORT(sk_ops) (__u16)((sk_ops)->remote_port >> 16)
#endif

#define GET_SKOPS_LOCAL_PORT(sk_ops) (__u16)((sk_ops)->local_port)

#define MAX_BUF_LEN 100
#define MAX_IP4_LEN 16
#define MAX_IP6_LEN 40
// Length in bytes of the binary data for an IPv4 address.
#define IPV4_BINARY_DATA_LEN 4
// Length in bytes of the binary data for an IPv6 address.
#define IPV6_BINARY_DATA_LEN 16
#define IPV4_VERSION         4
#define IPV6_VERSION         6

struct buf {
    char data[MAX_IP6_LEN];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct buf);
} tmp_buf SEC(".maps");

/*
 * This map is used to store different configuration options:
 * - key 0: Stores the log level
 * - key 1: Stores the authz (authorization) toggle
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct kmesh_config);
} kmesh_config_map SEC(".maps");

#if KERNEL_VERSION_HIGHER_5_13_0
static inline int convert_v4(char *data, __u32 *ip)
{
    int ret = 0;
    ret = BPF_SNPRINTF(data, MAX_IP4_LEN, "%pI4h", ip);
    return ret;
}
#else
static inline int convert_v4(char *data, __u32 *ip_ptr)
{
    __u32 ip = *ip_ptr;
    __u8 ip1 = (ip >> 24) & 0xFF;
    __u8 ip2 = (ip >> 16) & 0xFF;
    __u8 ip3 = (ip >> 8) & 0xFF;
    __u8 ip4 = (ip >> 0) & 0xFF;

    char tmp[MAX_IP4_LEN];
    tmp[2] = '0' + (ip1 % 10);
    ip1 /= 10;
    tmp[1] = '0' + (ip1 % 10);
    ip1 /= 10;
    tmp[0] = '0' + (ip1 % 10);
    tmp[3] = '.';

    tmp[6] = '0' + (ip2 % 10);
    ip2 /= 10;
    tmp[5] = '0' + (ip2 % 10);
    ip2 /= 10;
    tmp[4] = '0' + (ip2 % 10);
    tmp[7] = '.';

    tmp[10] = '0' + (ip3 % 10);
    ip3 /= 10;
    tmp[9] = '0' + (ip3 % 10);
    ip3 /= 10;
    tmp[8] = '0' + (ip3 % 10);
    tmp[11] = '.';

    tmp[14] = '0' + (ip4 % 10);
    ip4 /= 10;
    tmp[13] = '0' + (ip4 % 10);
    ip4 /= 10;
    tmp[12] = '0' + (ip4 % 10);

    *data++ = tmp[12];
    *data++ = tmp[13];
    *data++ = tmp[14];
    *data++ = tmp[11];
    *data++ = tmp[8];
    *data++ = tmp[9];
    *data++ = tmp[10];
    *data++ = tmp[7];
    *data++ = tmp[4];
    *data++ = tmp[5];
    *data++ = tmp[6];
    *data++ = tmp[3];
    *data++ = tmp[0];
    *data++ = tmp[1];
    *data++ = tmp[2];

    *data = '\0';
    return MAX_IP4_LEN;
}
#endif

#if KERNEL_VERSION_HIGHER_5_13_0
static inline int convert_v6(char *data, __u32 *ip6)
{
    int ret = 0;
    ret = BPF_SNPRINTF(data, MAX_IP6_LEN, "%pI6", ip6);
    return ret;
}
#else
static inline int convert_v6(char *data, __u32 *ip6)
{
    const char hex_digits[16] = "0123456789abcdef";
#pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++) {
        __u32 ip = *(ip6 + i);
        __u16 ip_1 = (ip >> 0) & 0xFFFF;
        __u16 ip_2 = (ip >> 16) & 0xFFFF;
        for (int j = 0; j < 2; j++) {
            __u16 ip_1 = (ip)&0xFFFF;
            __u8 h_1 = (ip_1 >> 0) & 0xFF;
            __u8 h_2 = (ip_1 >> 8) & 0xFF;
            *data++ = hex_digits[(h_1 >> 4) & 0xF];
            *data++ = hex_digits[(h_1 >> 0) & 0xF];
            *data++ = hex_digits[(h_2 >> 4) & 0xF];
            *data++ = hex_digits[(h_2 >> 0) & 0xF];
            *data++ = ':';
            ip = ip >> 16;
        }
    }
    data--;
    *data = '\0';
    return MAX_IP6_LEN;
}
#endif

/* 2001:0db8:3333:4444:CCCC:DDDD:EEEE:FFFF */
/* 192.168.000.001 */
static inline char *ip2str(__u32 *ip_ptr, bool v4)
{
    struct buf *buf;
    int zero = 0;
    int ret;
    buf = bpf_map_lookup_elem(&tmp_buf, &zero);
    if (!buf)
        return NULL;
    if (v4) {
        ret = convert_v4(buf->data, ip_ptr);
    } else {
        ret = convert_v6(buf->data, ip_ptr);
    }
    if (ret < 0)
        return NULL;
    return buf->data;
}

#endif // _COMMON_H_
