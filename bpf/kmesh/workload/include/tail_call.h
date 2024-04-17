/*
 * Copyright 2024 The Kmesh Authors.
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
 */

#ifndef _KMESH_WORKLOAD_TAIL_CALL_H_
#define _KMESH_WORKLOAD_TAIL_CALL_H_

#include "workload_common.h"

#define MAP_SIZE_OF_TAIL_CALL_PROG 4

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAP_SIZE_OF_TAIL_CALL_PROG);
    __uint(map_flags, 0);
} map_of_tail_call_prog SEC(".maps");

static inline void kmesh_workload_tail_call(ctx_buff_t *ctx, const __u32 index)
{
    bpf_tail_call(ctx, &map_of_tail_call_prog, index);
}

#endif