/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

package bpf

import (
	"codehub.com/mesh/pkg/logger"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go run github.com/cilium/ebpf/cmd/bpf2go --help
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang CgroupSock ../../bpf/kmesh/cgroup_sock.c -- -I../../bpf/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang Filter ../../bpf/kmesh/filter.c -- -I../../bpf/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang Cluster ../../bpf/kmesh/cluster.c -- -I../../bpf/include

const (
	pkgSubsys = "bpf"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
)

type BpfProgram struct {
	link link.Link
	objs *CgroupSockObjects
}

func AttachCgroupSock(cgroup2Path, bpffsPath string) (*BpfProgram, error) {
	fn := "cgroup_sock"

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	objs := &CgroupSockObjects{}
	if err := LoadCgroupSockObjects(objs, nil); err != nil {
		return nil, err
	}
	objs.Sock4Connect.Pin(bpffsPath + fn)

	cgopt := link.CgroupOptions {
		Path: cgroup2Path,
		Attach: ebpf.AttachCGroupInet4Connect,
		Program: objs.Sock4Connect,
	}

	lk, err := link.AttachCgroup(cgopt)
	if err != nil {
		return nil, err
	}

	bp := &BpfProgram{
		objs: objs,
		link: lk,
	}
	return bp, err
}

func (bp *BpfProgram) Close() error {
	if err := bp.objs.Close(); err != nil {
		return err
	}
	if err := bp.objs.Sock4Connect.Unpin(); err != nil {
		return err
	}
	return bp.link.Close()
}