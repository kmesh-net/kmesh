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

    return build_xdp_pkg(ctx, NULL, &l3, &l4, NULL, 0);
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
    check_xdp_pkg(ctx, &exp_status_code, NULL, NULL, NULL, NULL, 0);
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

    return build_xdp_pkg(ctx, NULL, &l3, &l4, NULL, 0);
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
    check_xdp_pkg(ctx, &exp_status_code, NULL, NULL, NULL, NULL, 0);
    test_finish();
}
