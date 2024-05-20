/*
 * Copyright 2023 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 * Author: nlgwcy
 * Create: 2022-02-17
 */

#ifndef _KMESH_TAIL_CALL_H_
#define _KMESH_TAIL_CALL_H_

#include "kmesh_common.h"

// same as linux/bpf.h MAX_TAIL_CALL_CNT
#define MAP_SIZE_OF_TAIL_CALL_PROG 32
#define MAP_SIZE_OF_TAIL_CALL_CTX  256

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAP_SIZE_OF_TAIL_CALL_PROG);
    __uint(map_flags, 0);
} map_of_tail_call_prog SEC(".maps");

static inline void kmesh_tail_call(ctx_buff_t *ctx, const __u32 index)
{
    bpf_tail_call(ctx, &map_of_tail_call_prog, index);
}

typedef struct {
    __u64 tail_call_index;
    address_t address;
} ctx_key_t;

typedef struct {
    union {
        // void *val;
        __u64 val;
        char data[BPF_DATA_MAX_LEN];
    };
    struct bpf_mem_ptr *msg;
} ctx_val_t;

// save temporary variables of tail_call
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(ctx_key_t));
    __uint(value_size, sizeof(ctx_val_t));
    __uint(max_entries, MAP_SIZE_OF_TAIL_CALL_CTX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_of_tail_call_ctx SEC(".maps");

static inline ctx_val_t *kmesh_tail_lookup_ctx(const ctx_key_t *key)
{
    return (ctx_val_t *)bpf_map_lookup_elem(&map_of_tail_call_ctx, key);
}

static inline void kmesh_tail_delete_ctx(const ctx_key_t *key)
{
    (void)bpf_map_delete_elem(&map_of_tail_call_ctx, key);
}

static inline int kmesh_tail_update_ctx(const ctx_key_t *key, const ctx_val_t *value)
{
    return (int)bpf_map_update_elem(&map_of_tail_call_ctx, key, value, BPF_ANY);
}

/*
    As a service mesh accelerator, Kmesh is expected to roll back to the original forwarding
    process when the acceleration forwarding logic fails. The execution result of the bpf
    tail caller must return BPF_OK.
*/
#define KMESH_TAIL_CALL_RET(ret) BPF_OK

/*
 *  To avoid interference between tail calls in different processes, we utilize
 *  the exclusivity of the eBPF program to the CPU to distinguish tail calls
 *  generated in different processes
 */
#define KMESH_TAIL_CALL_CTX_KEY(ckey, tail_call_idx, addr)                                                             \
    {                                                                                                                  \
        ckey.address = addr;                                                                                           \
        ckey.tail_call_index = tail_call_idx + (bpf_get_smp_processor_id() << 16);                                     \
    }

#define KMESH_TAIL_CALL_CTX_VAL(cval, m, v)                                                                            \
    {                                                                                                                  \
        cval.msg = m;                                                                                                  \
        cval.val = v;                                                                                                  \
    }

#define KMESH_TAIL_CALL_CTX_VALSTR(cval, m, s)                                                                         \
    {                                                                                                                  \
        cval.msg = m;                                                                                                  \
        (void)bpf_strncpy(cval.data, BPF_DATA_MAX_LEN, s);                                                             \
    }

#define KMESH_TAIL_CALL_WITH_CTX(tail_call_idx, ckey, cval)                                                            \
    {                                                                                                                  \
        ret = kmesh_tail_update_ctx(&ckey, &cval);                                                                     \
        if (ret != 0) {                                                                                                \
            BPF_LOG(ERR, COMMON, "kmesh tail update failed:%d\n", ret);                                                \
        } else {                                                                                                       \
            kmesh_tail_call(ctx, tail_call_idx);                                                                       \
            kmesh_tail_delete_ctx(&ckey);                                                                              \
        }                                                                                                              \
    }

#endif // _TAIL_CALL_H_
