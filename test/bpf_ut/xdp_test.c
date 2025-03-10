#include "ut_common.h"

#include <string.h>

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

#define FRONTEND_IP   0x0F00010A /* 10.0.1.15 */
#define FRONTEND_PORT 80
#define BACKEND_IP    0x0F00020A /* 10.2.0.15 */
#define BACKEND_PORT  8080
#ifndef IP_DF
#define IP_DF 0x4000
#endif

// TODO: Extract common packet generation logic and encapsulate it in pktgen.h
PKTGEN("xdp", "shutdown_in_userspace_should_shutdown")
int xdp_pktgen(__maybe_unused struct xdp_md *ctx)
{
    unsigned int data_len = ctx->data_end - ctx->data;

    int offset = offset = 4096 - 256 - 320 - data_len;
    bpf_xdp_adjust_tail(ctx, offset);

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) > data_end)
        return TEST_ERROR;

    struct ethhdr l2 = {
        .h_source = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        .h_dest = {0x12, 0x23, 0x34, 0x45, 0x56, 0x67},
        .h_proto = bpf_htons(ETH_P_IP)};
    memcpy(data, &l2, sizeof(struct ethhdr));
    data += sizeof(struct ethhdr);

    if (data + sizeof(struct iphdr) > data_end)
        return TEST_ERROR;

    struct iphdr l3 = {
        .version = 4,
        .ihl = 5,
        .tot_len = 40, /* 20 bytes l3 + 20 bytes l4 + 20 bytes data */
        .id = 0x5438,
        .frag_off = bpf_htons(IP_DF),
        .ttl = 64,
        .protocol = IPPROTO_TCP,
        .saddr = 0x0F00000A, /* 10.0.0.15 */
        .daddr = FRONTEND_IP,
    };
    memcpy(data, &l3, sizeof(struct iphdr));
    data += sizeof(struct iphdr);
    char tcp_data[20] = "Should not change!!";

    /* TCP header + data */
    if (data + (sizeof(struct tcphdr) + sizeof(tcp_data)) > data_end)
        return TEST_ERROR;

    struct tcphdr l4 = {
        .source = 23445,
        .dest = FRONTEND_PORT,
        .seq = 2922048129,
        .doff = 0, /* no options */
        .syn = 1,
        .window = 64240,
    };
    memcpy(data, &l4, sizeof(struct tcphdr));

    char *tcp_data_ptr = data + sizeof(tcp_data);

    memcpy(tcp_data_ptr, tcp_data, sizeof(tcp_data));

    data += sizeof(struct tcphdr) + sizeof(tcp_data);

    /* Shrink ctx to the exact size we used */
    offset = (int)((long)data - (long)ctx->data_end);
    bpf_xdp_adjust_tail(ctx, offset);
    return 0;
}

SETUP("xdp", "shutdown_in_userspace_should_shutdown")
int xdp_setup(__maybe_unused struct xdp_md *ctx)
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

CHECK("xdp", "shutdown_in_userspace_should_shutdown")
int xdp_check(__maybe_unused const struct xdp_md *ctx)
{
    test_init();

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // check status code
    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");

    __u32 *status_code = data;

    if (*status_code != XDP_PASS)
        test_fatal("status code != XDP_PASS");

    data += sizeof(__u32);
    // skip check ethhdr and iphdr
    data += sizeof(struct ethhdr);
    data += sizeof(struct iphdr);

    // check tcphdr
    if (data + sizeof(struct tcphdr) > data_end)
        test_fatal("ctx doesn't fit tcphdr");
    struct tcphdr *l4 = data;

    if (l4->fin != 0 || l4->syn != 0 || l4->rst != 1 || l4->psh != 0 || l4->ack != 0)
        test_fatal("l4->rst != 1");

    data += sizeof(struct tcphdr);

    // check body
    char msg[20] = "Should not change!!";

    if (data + sizeof(msg) > data_end)
        test_fatal("ctx doesn't fit tcp body");

    char *body = data;

    if (memcmp(body, msg, sizeof(msg)) != 0)
        test_fatal("body changed");

    test_finish();
}