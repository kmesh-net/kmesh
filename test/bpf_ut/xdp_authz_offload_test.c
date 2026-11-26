#include "ut_common.h"
#include "xdp_common.h"

#include <linux/bpf.h>

#include "workload/xdp.c"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(max_entries, 2);
    __array(values, int());
} entry_call_map SEC(".maps") = {
    .values =
        {
            [0] = &xdp_authz,
        },
};

/* 10.0.0.15:23445 -> 10.1.0.15:80 */
#define SRC_IP    0x0F00000A /* 10.0.0.15 */
#define SRC_PORT  23445
#define DEST_IP   0x0F00010A /* 10.1.0.15 */
#define DEST_PORT 80

PKTGEN("xdp", "3_deny_policy_matched")
int test1_pktgen(struct xdp_md *ctx)
{
    const struct iphdr l3 = {
        .version = 4,
        .ihl = 5,
        .tot_len = 40, /* 20 bytes l3 + 20 bytes l4 + 20 bytes data */
        .id = 0x5438,
        .frag_off = bpf_htons(IP_DF),
        .ttl = 64,
        .protocol = IPPROTO_TCP,
        .saddr = SRC_IP,
        .daddr = DEST_IP,
    };
    const struct tcphdr l4 = {
        .source = bpf_htons(SRC_PORT),
        .dest = bpf_htons(DEST_PORT),
        .seq = 2922048129,
        .doff = 0, /* no options */
        .syn = 1,
        .window = 64240,
    };

    return build_xdp_packet(ctx, NULL, &l3, &l4, NULL, 0);
}

JUMP("xdp", "3_deny_policy_matched")
int test1_jump(struct xdp_md *ctx)
{
    bpf_tail_call(ctx, &entry_call_map, 0);
    return TEST_ERROR;
}

CHECK("xdp", "3_deny_policy_matched")
int test1_check(const struct xdp_md *ctx)
{
    const __u32 exp_status_code = XDP_DROP;
    test_init();
    check_xdp_packet(ctx, &exp_status_code, NULL, NULL, NULL, NULL, 0);
    test_finish();
}

PKTGEN("xdp", "4_allow_policy_matched")
int test2_pktgen(struct xdp_md *ctx)
{
    const struct iphdr l3 = {
        .version = 4,
        .ihl = 5,
        .tot_len = 40, /* 20 bytes l3 + 20 bytes l4 + 20 bytes data */
        .id = 0x5438,
        .frag_off = bpf_htons(IP_DF),
        .ttl = 64,
        .protocol = IPPROTO_TCP,
        .saddr = SRC_IP,
        .daddr = DEST_IP,
    };
    const struct tcphdr l4 = {
        .source = bpf_htons(SRC_PORT),
        .dest = bpf_htons(DEST_PORT),
        .seq = 2922048129,
        .doff = 0, /* no options */
        .syn = 1,
        .window = 64240,
    };

    return build_xdp_packet(ctx, NULL, &l3, &l4, NULL, 0);
}

JUMP("xdp", "4_allow_policy_matched")
int test2_jump(struct xdp_md *ctx)
{
    bpf_tail_call(ctx, &entry_call_map, 0);
    return TEST_ERROR;
}

CHECK("xdp", "4_allow_policy_matched")
int test2_check(const struct xdp_md *ctx)
{
    const __u32 exp_status_code = XDP_PASS;
    test_init();
    check_xdp_packet(ctx, &exp_status_code, NULL, NULL, NULL, NULL, 0);
    test_finish();
}

/* [2001:db8::15]:23445 -> [2001:db8:1::15]:80 */
#define SRC_IP6                                                                                                        \
    {                                                                                                                  \
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x15                                                  \
    }
#define DEST_IP6                                                                                                       \
    {                                                                                                                  \
        0x20, 0x01, 0x0d, 0xb8, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x15                                               \
    }

#define xdp_ipv6_pktgen(ctx)                                                                                           \
    ({                                                                                                                 \
        const struct ipv6hdr l3 = {                                                                                    \
            .version = 6,                                                                                              \
            .payload_len = bpf_htons(sizeof(struct tcphdr)),                                                           \
            .nexthdr = IPPROTO_TCP,                                                                                    \
            .hop_limit = 64,                                                                                           \
            .saddr.in6_u.u6_addr8 = SRC_IP6,                                                                           \
            .daddr.in6_u.u6_addr8 = DEST_IP6,                                                                          \
        };                                                                                                             \
        const struct tcphdr l4 = {                                                                                     \
            .source = bpf_htons(SRC_PORT),                                                                             \
            .dest = bpf_htons(DEST_PORT),                                                                              \
            .seq = 2922048129,                                                                                         \
            .doff = 5,                                                                                                 \
            .syn = 1,                                                                                                  \
            .window = 64240,                                                                                           \
        };                                                                                                             \
        build_xdp_ipv6_packet(ctx, &l3, &l4);                                                                          \
    })

#define XDP_AUTHZ_IPV6_TEST(name, fn, exp)                                                                             \
    PKTGEN("xdp", name)                                                                                                \
    int fn##_pktgen(struct xdp_md *ctx)                                                                                \
    {                                                                                                                  \
        return xdp_ipv6_pktgen(ctx);                                                                                   \
    }                                                                                                                  \
                                                                                                                       \
    JUMP("xdp", name)                                                                                                  \
    int fn##_jump(struct xdp_md *ctx)                                                                                  \
    {                                                                                                                  \
        bpf_tail_call(ctx, &entry_call_map, 0);                                                                        \
        return TEST_ERROR;                                                                                             \
    }                                                                                                                  \
                                                                                                                       \
    CHECK("xdp", name)                                                                                                 \
    int fn##_check(const struct xdp_md *ctx)                                                                           \
    {                                                                                                                  \
        const __u32 exp_status_code = exp;                                                                             \
        test_init();                                                                                                   \
        check_xdp_packet(ctx, &exp_status_code, NULL, NULL, NULL, NULL, 0);                                            \
        test_finish();                                                                                                 \
    }

XDP_AUTHZ_IPV6_TEST("5_ipv6_deny_ip_blocks_matched", test5, XDP_DROP)
XDP_AUTHZ_IPV6_TEST("6_ipv6_deny_ip_blocks_host_bits_matched", test6, XDP_DROP)
XDP_AUTHZ_IPV6_TEST("7_ipv6_deny_not_ip_blocks_excluded", test7, XDP_PASS)
XDP_AUTHZ_IPV6_TEST("8_ipv6_deny_not_ip_blocks_matched", test8, XDP_DROP)
XDP_AUTHZ_IPV6_TEST("9_ipv6_allow_ip_blocks_host_bits_matched", test9, XDP_PASS)
