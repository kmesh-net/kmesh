/*
 * Copyright The Kmesh Authors.
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

#ifndef COVERAGE_CONFIG_H
#define COVERAGE_CONFIG_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// 覆盖率map，用于记录每行代码的执行次数
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10000); // 根据代码量调整
} coverage_map SEC(".maps");

// 覆盖率计数宏
#define COVERAGE_TRACK(line)                                                                                           \
    do {                                                                                                               \
        __u32 key = line;                                                                                              \
        __u64 *val = bpf_map_lookup_elem(&coverage_map, &key);                                                         \
        if (val) {                                                                                                     \
            (*val)++;                                                                                                  \
        }                                                                                                              \
    } while (0)

#endif // COVERAGE_CONFIG_H