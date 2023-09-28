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
 * Create: 2022-02-27
 */

// Package bpf2go  generate c to go struct
package bpf2go

// go run github.com/cilium/ebpf/cmd/bpf2go --help
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshCgroupSock ../cgroup_sock.c -- -I../include -I../../include -I../../../api/v2-c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshSockops ../sockops.c -- -I../include -I../../include -I../../../api/v2-c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshFilter ../filter.c -- -I../include -I../../include -I../../../api/v2-c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshRouteConfig ../route_config.c -- -I../include -I../../include -I../../../api/v2-c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshCluster ../cluster.c -- -I../include -I../../include -I../../../api/v2-c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshTracePoint ../tracepoint.c -- -I../include -I../../include
