/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#pragma once

#define build_tc_packet(ctx, p_ethhdr, p_iphdr, p_tcphdr, body, body_len)                                              \
    ({                                                                                                                 \
        int __ret = TEST_PASS;                                                                                         \
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
        /* Shrink data payload to the exact size we used */                                                            \
        bpf_skb_change_tail(ctx, data - (void *)(long)((ctx)->data), 0);                                               \
        __ret;                                                                                                         \
    })

#define check_tc_packet(ctx, exp_status_code, exp_ethhdr, exp_iphdr, exp_tcphdr, exp_body, exp_body_len)               \
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