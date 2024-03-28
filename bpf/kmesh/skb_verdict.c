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

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

static long (*bpf_migration_socket)(struct __sk_buff *skb) = (void *)163;

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
    bpf_migration_socket(skb);
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;