/**
 * @file workload_sendmsg_test.c
 * @brief Unit test support for sendmsg TLV encoding
 * 
 * This file provides mock data and function replacement to test sendmsg.c
 * without requiring real socket storage infrastructure.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_log.h"
#include "bpf_common.h"

/**
 * Mock socket storage for IPv4 test case
 * Simulates original destination: 8.8.8.8:53 via waypoint
 */
struct sock_storage_data mock_storage_ipv4 = {
    .via_waypoint = 1,                          // Mark as waypoint traffic
    .has_encoded = 0,                           // TLV not yet encoded
    .sk_tuple = {
        .ipv4 = {
            .daddr = __bpf_htonl(0x08080808),   // 8.8.8.8
            .dport = __bpf_htons(53)            // port 53
        },
    }
};

/**
 * Mock socket storage for IPv6 test case  
 * Simulates original destination: fc00:dead:beef:1234::abcd:53 via waypoint
 */
struct sock_storage_data mock_storage_ipv6 = {
    .via_waypoint = 1,
    .has_encoded = 0,
    .sk_tuple.ipv6 = {
        // fc00:dead:beef:1234::abcd
        .daddr = {__bpf_htonl(0xfc00dead), __bpf_htonl(0xbeef1234), 
                  __bpf_htonl(0x00000000), __bpf_htonl(0x0000abcd)},
        .dport = __bpf_htons(53), // port 53
    },
};

/**
 * Mock function to replace bpf_sk_storage_get for testing
 * 
 * In production: sendmsg.c gets original destination from socket storage
 * In testing: we can't set up real storage, so return predefined mock data
 * 
 * This allows testing TLV encoding with known input values for verification.
 */
static void *mock_bpf_sk_storage_get(void *map, void *sk, void *value, __u64 flags)
{
    void *storage = NULL;
    storage = bpf_sk_storage_get(map, sk, value, flags);
    if (!storage && map == &map_of_sock_storage) {
        struct bpf_sock *sk_sock = (struct bpf_sock *)sk;
        if (sk_sock->family == AF_INET) {
            storage = &mock_storage_ipv4;   // Return IPv4 mock data
        } else {
            storage = &mock_storage_ipv6;   // Return IPv6 mock data
        }
    }
    return storage;
}

// Replace real function with mock for testing
#define bpf_sk_storage_get mock_bpf_sk_storage_get

// Include actual sendmsg.c implementation with mock applied
#include "workload/sendmsg.c"