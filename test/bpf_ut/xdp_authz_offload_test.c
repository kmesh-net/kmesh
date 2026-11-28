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

/* True if xdp cached a verdict for the test tuple in map_of_auth_result. */
static __always_inline bool auth_result_cached(void)
{
    struct bpf_sock_tuple tuple = {0};

    tuple.ipv4.saddr = SRC_IP;
    tuple.ipv4.daddr = DEST_IP;
    tuple.ipv4.sport = SRC_PORT;
    tuple.ipv4.dport = DEST_PORT;
    return bpf_map_lookup_elem(&map_of_auth_result, &tuple) != NULL;
}

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

PKTGEN("xdp", "5_deny_principal_only_left_to_userspace")
int test3_pktgen(struct xdp_md *ctx)
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

JUMP("xdp", "5_deny_principal_only_left_to_userspace")
int test3_jump(struct xdp_md *ctx)
{
    bpf_tail_call(ctx, &entry_call_map, 0);
    return TEST_ERROR;
}

CHECK("xdp", "5_deny_principal_only_left_to_userspace")
int test3_check(const struct xdp_md *ctx)
{
    const __u32 exp_status_code = XDP_PASS;
    test_init();
    check_xdp_packet(ctx, &exp_status_code, NULL, NULL, NULL, NULL, 0);
    test_finish();
}

PKTGEN("xdp", "6_allow_principal_and_port_left_to_userspace")
int test4_pktgen(struct xdp_md *ctx)
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

JUMP("xdp", "6_allow_principal_and_port_left_to_userspace")
int test4_jump(struct xdp_md *ctx)
{
    bpf_tail_call(ctx, &entry_call_map, 0);
    return TEST_ERROR;
}

CHECK("xdp", "6_allow_principal_and_port_left_to_userspace")
int test4_check(const struct xdp_md *ctx)
{
    const __u32 exp_status_code = XDP_PASS;
    test_init();
    check_xdp_packet(ctx, &exp_status_code, NULL, NULL, NULL, NULL, 0);
    if (auth_result_cached())
        test_fatal("xdp cached a verdict, expected the decision to be left to userspace");
    test_finish();
}

PKTGEN("xdp", "7_deny_principal_then_allow_port_left_to_userspace")
int test5_pktgen(struct xdp_md *ctx)
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

JUMP("xdp", "7_deny_principal_then_allow_port_left_to_userspace")
int test5_jump(struct xdp_md *ctx)
{
    bpf_tail_call(ctx, &entry_call_map, 0);
    return TEST_ERROR;
}

CHECK("xdp", "7_deny_principal_then_allow_port_left_to_userspace")
int test5_check(const struct xdp_md *ctx)
{
    const __u32 exp_status_code = XDP_PASS;
    test_init();
    check_xdp_packet(ctx, &exp_status_code, NULL, NULL, NULL, NULL, 0);
    if (auth_result_cached())
        test_fatal("xdp cached a verdict, expected the decision to be left to userspace");
    test_finish();
}
