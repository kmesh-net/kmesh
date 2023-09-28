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
 */

static void *(*bpf_strncpy)(char *dst, __u32 dst_size, char *src) = (void *)210;
static void *(*bpf_strnstr)(void *s1, void *s2, __u32 size) = (void *)211;
static __u64 (*bpf_strnlen)(char *buff, __u32 size) = (void *)212;
static long(*bpf_parse_header_msg)(struct bpf_mem_ptr *msg) = (void *)213;
static void *(*bpf_get_msg_header_element)(void *name) = (void *)214;
