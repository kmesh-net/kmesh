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

/*
 * Policies that only use not_source_ips / not_destination_ips.
 * The packet is always 10.0.0.15:23445 -> 10.1.0.15:80.
 */
#define XDP_AUTHZ_IP_TEST(prefix, test_name, exp_code)                                                                 \
    PKTGEN("xdp", test_name)                                                                                           \
    int prefix##_pktgen(struct xdp_md *ctx)                                                                            \
    {                                                                                                                  \
        const struct iphdr l3 = {                                                                                      \
            .version = 4,                                                                                              \
            .ihl = 5,                                                                                                  \
            .tot_len = 40,                                                                                             \
            .id = 0x5438,                                                                                              \
            .frag_off = bpf_htons(IP_DF),                                                                              \
            .ttl = 64,                                                                                                 \
            .protocol = IPPROTO_TCP,                                                                                   \
            .saddr = SRC_IP,                                                                                           \
            .daddr = DEST_IP,                                                                                          \
        };                                                                                                             \
        const struct tcphdr l4 = {                                                                                     \
            .source = bpf_htons(SRC_PORT),                                                                             \
            .dest = bpf_htons(DEST_PORT),                                                                              \
            .seq = 2922048129,                                                                                         \
            .doff = 0,                                                                                                 \
            .syn = 1,                                                                                                  \
            .window = 64240,                                                                                           \
        };                                                                                                             \
        return build_xdp_packet(ctx, NULL, &l3, &l4, NULL, 0);                                                         \
    }                                                                                                                  \
    JUMP("xdp", test_name)                                                                                             \
    int prefix##_jump(struct xdp_md *ctx)                                                                              \
    {                                                                                                                  \
        bpf_tail_call(ctx, &entry_call_map, 0);                                                                        \
        return TEST_ERROR;                                                                                             \
    }                                                                                                                  \
    CHECK("xdp", test_name)                                                                                            \
    int prefix##_check(const struct xdp_md *ctx)                                                                       \
    {                                                                                                                  \
        const __u32 exp_status_code = exp_code;                                                                        \
        test_init();                                                                                                   \
        check_xdp_packet(ctx, &exp_status_code, NULL, NULL, NULL, NULL, 0);                                            \
        test_finish();                                                                                                 \
    }

/* DENY notSourceIp 192.168.0.0/16: source is outside the range, so the rule matches. */
XDP_AUTHZ_IP_TEST(test5, "5_deny_not_source_ip_outside_range", XDP_DROP)
/* DENY notSourceIp 10.0.0.0/8: source is inside the range, so the rule does not match. */
XDP_AUTHZ_IP_TEST(test6, "6_deny_not_source_ip_inside_range", XDP_PASS)
/* ALLOW notSourceIp 192.168.0.0/16: source is outside the range, so the rule matches. */
XDP_AUTHZ_IP_TEST(test7, "7_allow_not_source_ip_outside_range", XDP_PASS)
/* ALLOW notSourceIp 10.0.0.0/8: source is inside the range, so the rule does not match. */
XDP_AUTHZ_IP_TEST(test8, "8_allow_not_source_ip_inside_range", XDP_DROP)
/* DENY notDestinationIp 10.2.0.0/16: destination is outside the range, so the rule matches. */
XDP_AUTHZ_IP_TEST(test9, "9_deny_not_destination_ip_outside_range", XDP_DROP)
