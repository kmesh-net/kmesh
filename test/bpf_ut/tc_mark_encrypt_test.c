#include "ut_common.h"
#include "tc_common.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <netinet/tcp.h>

#include "general/tc_mark_encrypt.c"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(max_entries, 2);
    __array(values, int());
} entry_call_map SEC(".maps") = {
    .values =
        {
            [0] = &tc_mark_encrypt,
        },
};

/* 10.0.0.15:23445 -> 10.1.0.15:80 */
#define SRC_IP    0x0F00000A /* 10.0.0.15 */
#define SRC_PORT  23445
#define DEST_IP   0x0F00010A /* 10.1.0.15 */
#define DEST_PORT 80

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
    .doff = 0,
    .syn = 1,
    .window = 64240,
};
const char body[20] = "Should not change!!";

PKTGEN("tc", "tc_mark_encrypt")
int test1_pktgen(struct __sk_buff *ctx)
{
    return build_tc_packet(ctx, &l2, &l3, &l4, body, (uint)sizeof(body));
}

JUMP("tc", "tc_mark_encrypt")
int test1_jump(struct __sk_buff *ctx)
{
    // build context
    struct lpm_key key = {0};
    key.trie_key.prefixlen = 32;
    key.ip.ip4 = DEST_IP;
    __u32 value = 1;
    bpf_map_update_elem(&map_of_nodeinfo, &key, &value, BPF_ANY);

    bpf_tail_call(ctx, &entry_call_map, 0);
    return TEST_ERROR;
}

CHECK("tc", "tc_mark_encrypt")
int test1_check(struct __sk_buff *ctx)
{
    const __u32 expected_status_code = TC_ACT_OK;

    test_init();

    check_tc_packet(ctx, &expected_status_code, &l2, &l3, &l4, body, (uint)sizeof(body));
    if (ctx->mark != 0x00e0)
        test_fatal("ctx->mark mismatch, expected 0x00e0, got %u", ctx->mark);

    test_finish();
}
