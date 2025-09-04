#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_log.h"
#include "bpf_common.h"
volatile __u32 current_direction;
struct sock_storage_data mock_storage = {
    .connect_ns = 0,
    .direction = 1,
    .connect_success = 1,
    .via_waypoint = 1,
    .has_encoded = 0,
    .last_report_ns = 5 * 1000000000ULL,
    .sk_tuple = {
        .ipv4 = {
            .daddr = __bpf_htonl(0x08080808), // 8.8.8.8
            .dport = __bpf_htons(53),         // 53
        }}};
static void *mock_bpf_sk_storage_get(void *map, void *sk, void *value, __u64 flags)
{
    struct bpf_sock *sk_sock = (struct bpf_sock *)sk;
    void *storage = NULL;
    if (map == &map_of_sock_storage) {
        mock_storage.direction = current_direction;
        storage = &mock_storage;
    }

    return storage;
}

#define bpf_sk_storage_get mock_bpf_sk_storage_get
#include "workload/cgroup_skb.c"