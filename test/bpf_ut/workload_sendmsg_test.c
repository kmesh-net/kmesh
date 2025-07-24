#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_log.h"
#include "bpf_common.h"
struct sock_storage_data mock_storage = {
    .via_waypoint = 1,
    .has_encoded = 0,
    .sk_tuple = {
        .ipv4 =
            {
                .daddr = __bpf_htonl(0x08080808), // 8.8.8.8
                .dport = __bpf_htons(53)          // port 53
            },
    }};

static void *mock_bpf_sk_storage_get(void *map, void *sk, void *value, __u64 flags)
{
    void *storage = NULL;
    storage = bpf_sk_storage_get(map, sk, value, flags);
    if (!storage && map == &map_of_sock_storage) {
        storage = &mock_storage;
    }
    return storage;
}

#define bpf_sk_storage_get mock_bpf_sk_storage_get

#include "workload/sendmsg.c"