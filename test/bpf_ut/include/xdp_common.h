/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#pragma once

#define build_xdp_pkg(ctx, p_ethhdr, p_iphdr, p_tcphdr, body, body_len)                                                \
    ({                                                                                                                 \
        int __ret = TEST_PASS;                                                                                         \
        unsigned int data_len = (ctx)->data_end - (ctx)->data;                                                         \
                                                                                                                       \
        /* Adjust packet size - ensure we have enough space */                                                         \
        int offset = 4096 - 256 - 320 - data_len;                                                                      \
        if (bpf_xdp_adjust_tail(ctx, offset) != 0) {                                                                   \
            return TEST_ERROR;                                                                                         \
        }                                                                                                              \
                                                                                                                       \
        void *data = (void *)(long)((ctx)->data);                                                                      \
        void *data_end = (void *)(long)((ctx)->data_end);                                                              \
                                                                                                                       \
        /* Set Ethernet header */                                                                                      \
        if (data + sizeof(struct ethhdr) > data_end)                                                                   \
            return TEST_ERROR;                                                                                         \
        if (p_ethhdr) {                                                                                                \
            bpf_memcpy(data, (p_ethhdr), sizeof(struct ethhdr));                                                       \
        } else {                                                                                                       \
            /* Default Ethernet header */                                                                              \
            __maybe_unused const struct ethhdr default_eth = {                                                         \
                .h_source = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},                                                      \
                .h_dest = {0x12, 0x23, 0x34, 0x45, 0x56, 0x67},                                                        \
                .h_proto = bpf_htons(ETH_P_IP)};                                                                       \
            bpf_memcpy(data, &default_eth, sizeof(struct ethhdr));                                                     \
        }                                                                                                              \
        data += sizeof(struct ethhdr);                                                                                 \
                                                                                                                       \
        /* Set IP header */                                                                                            \
        if (data + sizeof(struct iphdr) > data_end)                                                                    \
            return TEST_ERROR;                                                                                         \
        if (p_iphdr) {                                                                                                 \
            bpf_memcpy(data, (p_iphdr), sizeof(struct iphdr));                                                         \
        } else {                                                                                                       \
            /* Default IP header */                                                                                    \
            __maybe_unused const unsigned int ip_payload_size = sizeof(struct tcphdr) + (body ? body_len : 0);         \
            __maybe_unused const struct iphdr default_ip = {                                                           \
                .version = 4,                                                                                          \
                .ihl = 5,                                                                                              \
                .tot_len = bpf_htons(sizeof(struct iphdr) + ip_payload_size),                                          \
                .id = 0x5438,                                                                                          \
                .frag_off = bpf_htons(IP_DF),                                                                          \
                .ttl = 64,                                                                                             \
                .protocol = IPPROTO_TCP,                                                                               \
                .saddr = 0x0F00000A, /* 10.0.0.15 */                                                                   \
                .daddr = 0x0100000A  /* 10.0.0.1 - assuming DEST_IP */                                                 \
            };                                                                                                         \
            bpf_memcpy(data, &default_ip, sizeof(struct iphdr));                                                       \
        }                                                                                                              \
        data += sizeof(struct iphdr);                                                                                  \
                                                                                                                       \
        /* Set TCP header */                                                                                           \
        if (data + sizeof(struct tcphdr) > data_end)                                                                   \
            return TEST_ERROR;                                                                                         \
        if (p_tcphdr) {                                                                                                \
            bpf_memcpy(data, (p_tcphdr), sizeof(struct tcphdr));                                                       \
        } else {                                                                                                       \
            /* Default TCP header */                                                                                   \
            __maybe_unused const struct tcphdr default_tcp = {                                                         \
                .source = bpf_htons(23445),                                                                            \
                .dest = bpf_htons(80), /* assuming DEST_PORT */                                                        \
                .seq = 2922048129,                                                                                     \
                .doff = 5, /* 5 * 4 = 20 bytes, no options */                                                          \
                .syn = 1,                                                                                              \
                .window = 64240};                                                                                      \
            bpf_memcpy(data, &default_tcp, sizeof(struct tcphdr));                                                     \
        }                                                                                                              \
        data += sizeof(struct tcphdr);                                                                                 \
                                                                                                                       \
        /* Set payload data */                                                                                         \
        if (body && body_len > 0) {                                                                                    \
            if (data + body_len > data_end)                                                                            \
                return TEST_ERROR;                                                                                     \
            bpf_memcpy(data, body, body_len);                                                                          \
            data += body_len;                                                                                          \
        }                                                                                                              \
        /* Shrink ctx to the exact size we used */                                                                     \
        offset = (int)((long)data - (long)data_end);                                                                   \
        bpf_xdp_adjust_tail(ctx, offset);                                                                              \
        __ret;                                                                                                         \
    })

/**
 * @brief Verifies that a processed packet matches expected values
 *
 * This macro checks if the XDP packet matches expected values by sequentially validating:
 * - Status code
 * - Ethernet header
 * - IP header
 * - TCP header
 * - Packet body (payload data)
 *
 * @param ctx              XDP context containing packet data
 * @param exp_status_code  Expected status code pointer (if NULL, status code check is skipped)
 * @param exp_ethhdr       Expected Ethernet header pointer (if NULL, Ethernet header check is skipped)
 * @param exp_iphdr        Expected IP header pointer (if NULL, IP header check is skipped)
 * @param exp_tcphdr       Expected TCP header pointer (if NULL, TCP header check is skipped)
 * @param exp_body         Expected packet body/payload pointer (if NULL, body check is skipped)
 * @param exp_body_len     Length of the expected body data to check
 *
 * The macro fails the test with an error message if any of the checks fail or if there are
 * bounds violations when accessing packet data.
 */
#define check_xdp_pkg(ctx, exp_status_code, exp_ethhdr, exp_iphdr, exp_tcphdr, exp_body, exp_body_len)                 \
    do {                                                                                                               \
        void *data = (void *)(long)((ctx)->data);                                                                      \
        void *data_end = (void *)(long)((ctx)->data_end);                                                              \
                                                                                                                       \
        if (data + sizeof(__u32) > data_end)                                                                           \
            test_fatal("status code out of bounds");                                                                   \
        if (exp_status_code) {                                                                                         \
            __u32 *status_code = (__u32 *)data;                                                                        \
            if (*status_code != *(exp_status_code))                                                                    \
                test_fatal("status code mismatch, expected %u, got %u", *(exp_status_code), *status_code);             \
        }                                                                                                              \
        data += sizeof(__u32);                                                                                         \
                                                                                                                       \
        if (data + sizeof(struct ethhdr) > data_end)                                                                   \
            test_fatal("ethhdr out of bounds");                                                                        \
        if (exp_ethhdr) {                                                                                              \
            struct ethhdr *eth = (struct ethhdr *)data;                                                                \
            if (memcmp(eth, (exp_ethhdr), sizeof(struct ethhdr)) != 0)                                                 \
                test_fatal("ethhdr mismatch");                                                                         \
        }                                                                                                              \
        data += sizeof(struct ethhdr);                                                                                 \
                                                                                                                       \
        if (data + sizeof(struct iphdr) > data_end)                                                                    \
            test_fatal("iphdr out of bounds");                                                                         \
        if (exp_iphdr) {                                                                                               \
            struct iphdr *ip = (struct iphdr *)data;                                                                   \
            if (memcmp(ip, (exp_iphdr), sizeof(struct iphdr)) != 0)                                                    \
                test_fatal("iphdr mismatch");                                                                          \
        }                                                                                                              \
        data += sizeof(struct iphdr);                                                                                  \
                                                                                                                       \
        if (data + sizeof(struct tcphdr) > data_end)                                                                   \
            test_fatal("tcphdr out of bounds");                                                                        \
        if (exp_tcphdr) {                                                                                              \
            struct tcphdr *tcp = (struct tcphdr *)data;                                                                \
            if (memcmp(tcp, (exp_tcphdr), sizeof(struct tcphdr)) != 0)                                                 \
                test_fatal("tcphdr mismatch");                                                                         \
        }                                                                                                              \
        data += sizeof(struct tcphdr);                                                                                 \
        if (data + exp_body_len > data_end)                                                                            \
            test_fatal("body out of bounds");                                                                          \
        if (exp_body) {                                                                                                \
            char *body = (char *)data;                                                                                 \
            if (memcmp(body, (exp_body), exp_body_len) != 0)                                                           \
                test_fatal("body mismatch");                                                                           \
        }                                                                                                              \
    } while (0)
