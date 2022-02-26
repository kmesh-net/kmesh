/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2021-10-09
 */

package bpf2go

//go run github.com/cilium/ebpf/cmd/bpf2go --help
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE CgroupSock ../cgroup_sock.c -- -I../../include -I../../../api/v1-c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE Filter ../filter.c -- -I../../include -I../../../api/v1-c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang --cflags $EXTRA_CFLAGS --cflags $EXTRA_CDEFINE Cluster ../cluster.c -- -I../../include -I../../../api/v1-c
