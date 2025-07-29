#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_log.h"
#include "bpf_common.h"
struct sock_storage_data mock_storage_ipv4 = {
    .via_waypoint = 1,
    .has_encoded = 0,
    .sk_tuple = {
        .ipv4 =
            {
                .daddr = __bpf_htonl(0x08080808), // 8.8.8.8
                .dport = __bpf_htons(53)          // port 53
            },
    }};
struct sock_storage_data mock_storage_ipv6 = {
    .via_waypoint = 1,
    .has_encoded = 0,
    .sk_tuple.ipv6 =
        {
            // fc00:dead:beef:1234::abcd
            .daddr =
                {__bpf_htonl(0xfc00dead), __bpf_htonl(0xbeef1234), __bpf_htonl(0x00000000), __bpf_htonl(0x0000abcd)},
            .dport = __bpf_htons(53), // port 53
        },
};
static void *mock_bpf_sk_storage_get(void *map, void *sk, void *value, __u64 flags)
{
    void *storage = NULL;
    storage = bpf_sk_storage_get(map, sk, value, flags);
    if (!storage && map == &map_of_sock_storage) {
        struct bpf_sock *sk_sock = (struct bpf_sock *)sk;
        if (sk_sock->family == AF_INET) {
            storage = &mock_storage_ipv4;
        } else {
            storage = &mock_storage_ipv6;
        }
    }
    return storage;
}

#define bpf_sk_storage_get mock_bpf_sk_storage_get

#include "workload/sendmsg.c"