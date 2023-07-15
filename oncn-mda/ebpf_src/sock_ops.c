/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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

#include <stddef.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "mesh_accelerate.h"

SEC("sockops")
int SOCK_OPS_NAME(struct bpf_sock_ops* const skops)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 1;
