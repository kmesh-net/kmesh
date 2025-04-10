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

// Package bpf2go  generate c to go struct
package bpf2go

// go run github.com/cilium/ebpf/cmd/bpf2go --help
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir kernelnative/$ENHANCED_KERNEL --go-package $ENHANCED_KERNEL -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshCgroupSock ../ads/cgroup_sock.c -- -I../ads/include -I../../include -I../../../api/v2-c -DCGROUP_SOCK_MANAGE -DKERNEL_VERSION_HIGHER_5_13_0=1
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir dualengine --go-package dualengine -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshCgroupSockWorkload ../workload/cgroup_sock.c -- -I../workload/include -I../../include -I../probes -DKERNEL_VERSION_HIGHER_5_13_0=1
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir kernelnative/$ENHANCED_KERNEL --go-package $ENHANCED_KERNEL -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshSockops ../ads/sockops.c -- -I../ads/include -I../../include -I../../../api/v2-c -DKERNEL_VERSION_HIGHER_5_13_0=1
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir dualengine --go-package dualengine -cc clang --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshSockopsWorkload ../workload/sockops.c -- -I../workload/include -I../../include -I../probes -DKERNEL_VERSION_HIGHER_5_13_0=1
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir dualengine --go-package dualengine -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshXDPAuth ../workload/xdp.c -- -I../workload/include -I../../include -I../../../api/v2-c -DKERNEL_VERSION_HIGHER_5_13_0=1
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir dualengine --go-package dualengine -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshSendmsg ../workload/sendmsg.c -- -I../workload/include -I../../include -DKERNEL_VERSION_HIGHER_5_13_0=1
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir dualengine --go-package dualengine -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshCgroupSkb ../workload/cgroup_skb.c -- -I../workload/include -I../../include -I../probes -DKERNEL_VERSION_HIGHER_5_13_0=1
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir general --go-package general -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshTcMarkEncrypt ../general/tc_mark_encrypt.c -- -I../general/include -I../../include -DKERNEL_VERSION_HIGHER_5_13_0=1
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir general --go-package general -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshTcMarkDecrypt ../general/tc_mark_decrypt.c -- -I../general/include -I../../include -DKERNEL_VERSION_HIGHER_5_13_0=1

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir kernelnative/$ENHANCED_KERNEL --go-package $ENHANCED_KERNEL -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshCgroupSockCompat ../ads/cgroup_sock.c -- -I../ads/include -I../../include -I../../../api/v2-c -DCGROUP_SOCK_MANAGE -DKERNEL_VERSION_HIGHER_5_13_0=0
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir dualengine --go-package dualengine -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshCgroupSockWorkloadCompat ../workload/cgroup_sock.c -- -I../workload/include -I../../include -I../probes -DKERNEL_VERSION_HIGHER_5_13_0=0
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir kernelnative/$ENHANCED_KERNEL --go-package $ENHANCED_KERNEL -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshSockopsCompat ../ads/sockops.c -- -I../ads/include -I../../include -I../../../api/v2-c -DKERNEL_VERSION_HIGHER_5_13_0=0
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir dualengine --go-package dualengine  -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshSockopsWorkloadCompat ../workload/sockops.c -- -I../workload/include -I../../include -I../probes -DKERNEL_VERSION_HIGHER_5_13_0=0
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir dualengine --go-package dualengine -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshXDPAuthCompat ../workload/xdp.c -- -I../workload/include -I../../include -I../../../api/v2-c -DKERNEL_VERSION_HIGHER_5_13_0=0
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir dualengine --go-package dualengine -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshSendmsgCompat ../workload/sendmsg.c -- -I../workload/include -I../../include -DKERNEL_VERSION_HIGHER_5_13_0=0
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir dualengine --go-package dualengine -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshCgroupSkbCompat ../workload/cgroup_skb.c -- -I../workload/include -I../../include -I../probes -DKERNEL_VERSION_HIGHER_5_13_0=0
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir general --go-package general -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshTcMarkEncryptCompat ../general/tc_mark_encrypt.c -- -I../general/include -I../../include -DKERNEL_VERSION_HIGHER_5_13_0=0
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir general --go-package general -cc clang  --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE KmeshTcMarkDecryptCompat ../general/tc_mark_decrypt.c -- -I../general/include -I../../include -DKERNEL_VERSION_HIGHER_5_13_0=0
