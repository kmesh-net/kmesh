// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

// Package bpf2go  generate c to go struct
package bpf2go

// go run github.com/cilium/ebpf/cmd/bpf2go --help
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshCgroupSock ../ads/cgroup_sock.c -- -I../ads/include -I../../include -I../../../api/v2-c -DCGROUP_SOCK_MANAGE
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshCgroupSockWorkload ../workload/cgroup_sock.c -- -I../workload/include -I../../include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshSockops ../ads/sockops.c -- -I../ads/include -I../../include -I../../../api/v2-c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshTracePoint ../ads/tracepoint.c -- -I../ads/include -I../../include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshSockopsWorkload ../workload/sockops.c -- -I../workload/include -I../../include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshXDPAuth ../workload/xdp.c -- -I../workload/include -I../../include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshSendmsg ../workload/sendmsg.c -- -I../workload/include -I../../include
