#include "ut_common.h"
#include "xdp_common.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>

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

// 1_shutdown_in_userspace__should_shutdown
PKTGEN("xdp", "1_shutdown_in_userspace__should_shutdown")
int test1_pktgen(struct xdp_md *ctx)
{
    const struct ethhdr l2 = {
        .h_source = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        .h_dest = {0x12, 0x23, 0x34, 0x45, 0x56, 0x67},
        .h_proto = bpf_htons(ETH_P_IP)};
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
    const char body[20] = "Should not change!!";

    return build_xdp_packet(ctx, &l2, &l3, &l4, body, (uint)sizeof(body));
}

JUMP("xdp", "1_shutdown_in_userspace__should_shutdown")
int test1_jump(struct xdp_md *ctx)
{
    /* build the test context */
    struct bpf_sock_tuple tuple_key = {0};
    struct xdp_info info = {0};
    __u32 auth_deny = AUTH_DENY;
    if (construct_tuple_key(ctx, &tuple_key, &info) != PARSER_SUCC) {
        BPF_LOG(ERR, UNITTEST, "failed to construct tuple key\n");
        return TEST_ERROR;
    }
    if (bpf_map_update_elem(&map_of_auth_result, &tuple_key, &auth_deny, BPF_ANY) != 0) {
        BPF_LOG(ERR, UNITTEST, "failed to update auth result in map_of_auth_result");
        return TEST_ERROR;
    }

    /* Jump into the entrypoint */
    bpf_tail_call(ctx, &entry_call_map, 0);
    /* Fail if we didn't jump */
    return TEST_ERROR;
}

CHECK("xdp", "1_shutdown_in_userspace__should_shutdown")
int test1_check(const struct xdp_md *ctx)
{
    const __u32 expected_status_code = XDP_PASS;
    const struct ethhdr expected_ethhdr = {
        .h_source = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        .h_dest = {0x12, 0x23, 0x34, 0x45, 0x56, 0x67},
        .h_proto = bpf_htons(ETH_P_IP)};
    const struct iphdr expected_iphdr = {
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
    const struct tcphdr expected_tcphdr = {
        .source = bpf_htons(SRC_PORT),
        .dest = bpf_htons(DEST_PORT),
        .seq = 2922048129,
        .doff = 0,
        .rst = 1, // RST bit set
        .window = 64240,
    };
    const char expected_body[20] = "Should not change!!";
    test_init();

    check_xdp_packet(
        ctx,
        &expected_status_code,
        &expected_ethhdr,
        &expected_iphdr,
        &expected_tcphdr,
        expected_body,
        sizeof(expected_body));

    test_finish();
}

// 2_shutdown_in_userspace__should_not_shutdown
PKTGEN("xdp", "2_shutdown_in_userspace__should_not_shutdown")
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

JUMP("xdp", "2_shutdown_in_userspace__should_not_shutdown")
int test2_jump(struct xdp_md *ctx)
{
    /* Jump into the entrypoint */
    bpf_tail_call(ctx, &entry_call_map, 0);
    /* Fail if we didn't jump */
    return TEST_ERROR;
}

CHECK("xdp", "2_shutdown_in_userspace__should_not_shutdown")
int test2_check(const struct xdp_md *ctx)
{
    const __u32 expected_status_code = XDP_PASS;
    const struct tcphdr expected_tcphdr = {
        .source = bpf_htons(23445),
        .dest = bpf_htons(DEST_PORT),
        .seq = 2922048129,
        .doff = 0, /* no options */
        .syn = 1,
        .window = 64240,
    };
    test_init();

    check_xdp_packet(ctx, &expected_status_code, NULL, NULL, &expected_tcphdr, NULL, 0);

    test_finish();
}
