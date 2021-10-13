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
	"reflect"
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

type bpfProgram struct {
	CgroupSockPrograms
	FilterPrograms
	ClusterPrograms
}

type bpfMap struct {
	CgroupSockMaps
	//FilterMaps
	//ClusterMaps
}

type BpfInfo struct {
	BpffsPath	string
	Cgroup2Path	string
	AttachType	ebpf.AttachType
}

type BpfObject struct {
	link	link.Link
	progs	bpfProgram
	maps	bpfMap
	info 	BpfInfo
}

func Load(info *BpfInfo) (*BpfObject, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	obj := &BpfObject{}
	obj.info = *info
	obj.info.AttachType = ebpf.AttachCGroupInet4Connect

	sockObjs := &CgroupSockObjects{}
	if err := LoadCgroupSockObjects(sockObjs, nil); err != nil {
		return nil, err
	}
	obj.progs.CgroupSockPrograms = sockObjs.CgroupSockPrograms
	obj.maps.CgroupSockMaps = sockObjs.CgroupSockMaps

	return obj, nil
}

func (obj *BpfObject) pinPrograms() error {
	var (
		err		error
		pInfo	*ebpf.ProgramInfo
	)

	if pInfo, err = obj.progs.Sock4Connect.Info(); err != nil {
		return err
	}
	if err = obj.progs.Sock4Connect.Pin(obj.info.BpffsPath + pInfo.Name); err != nil {
		return err
	}

	return nil
}

func (obj *BpfObject) unpinPrograms() error {
	if err := obj.progs.Sock4Connect.Unpin(); err != nil {
		return err
	}

	return nil
}

func (obj *BpfObject) pinMaps() error {
	var (
		err		error
		mInfo	*ebpf.MapInfo
	)

	value := reflect.ValueOf(obj.maps.CgroupSockMaps)
	for i := 0; i < value.NumField(); i++ {
		m := value.Field(i).Interface().(*ebpf.Map)
		if mInfo, err = m.Info(); err != nil {
			return err
		}
		if err = m.Pin(obj.info.BpffsPath + mInfo.Name); err != nil {
			return err
		}
	}

	return nil
}

func (obj *BpfObject) unpinMaps() error {
	value := reflect.ValueOf(obj.maps.CgroupSockMaps)
	for i := 0; i < value.NumField(); i++ {
		m := value.Field(i).Interface().(*ebpf.Map)
		if err := m.Unpin(); err != nil {
			return err
		}
	}

	return nil
}

func (obj *BpfObject) Setup() error {
	if err := obj.pinPrograms(); err != nil {
		return err
	}

	return obj.pinMaps()
}

func (obj *BpfObject) Attach() error {
	cgopt := link.CgroupOptions {
		Path:		obj.info.Cgroup2Path,
		Attach:		obj.info.AttachType,
		Program:	obj.progs.Sock4Connect,
	}

	lk, err := link.AttachCgroup(cgopt)
	if err != nil {
		return err
	}
	obj.link = lk

	return nil
}

func (obj *BpfObject) Close() error {
	if err := obj.progs.CgroupSockPrograms.Close(); err != nil {
		return err
	}
	if err := obj.maps.CgroupSockMaps.Close(); err != nil {
		return err
	}

	if err := obj.unpinPrograms(); err != nil {
		return err
	}
	if err := obj.unpinMaps(); err != nil {
		return err
	}

	return obj.link.Close()
}