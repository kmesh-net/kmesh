#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_log.h"
#include "bpf_common.h"

// mock bpf_sk_storage_get
struct sock_storage_data mock_storage = {
    .via_waypoint = 1,
};

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

#include "workload/sockops.c"