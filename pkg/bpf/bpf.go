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
	"os"
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

type BpfInfo struct {
	BpffsPath	string
	Cgroup2Path	string
	AttachType	ebpf.AttachType
}
type bpfProgramObjects struct {
	CgroupSockObjects
	FilterObjects
	ClusterObjects
}
type BpfObject struct {
	info 		BpfInfo
	progObjs	bpfProgramObjects
	link		link.Link
}

func pinPrograms(value *reflect.Value, path string) error {
	for i := 0; i < value.NumField(); i++ {
		tp := value.Field(i).Interface().(*ebpf.Program)
		info, err := tp.Info()
		if err != nil {
			log.Warn(err)
		}
		if err := tp.Pin(path + info.Name); err != nil {
			log.Warn(err)
		}
	}

	return nil
}

func unpinPrograms(value *reflect.Value) error {
	for i := 0; i < value.NumField(); i++ {
		tp := value.Field(i).Interface().(*ebpf.Program)
		if err := tp.Unpin(); err != nil {
			log.Warn(err)
		}
	}

	return nil
}

func pinMaps(value *reflect.Value, path string) error {
	for i := 0; i < value.NumField(); i++ {
		tp := value.Field(i).Interface().(*ebpf.Map)
		info, err := tp.Info()
		if err != nil {
			log.Warn(err)
		}
		if err := tp.Pin(path + info.Name); err != nil {
			log.Warn(err)
		}
	}

	return nil
}

func unpinMaps(value *reflect.Value) error {
	for i := 0; i < value.NumField(); i++ {
		tp := value.Field(i).Interface().(*ebpf.Map)
		if err := tp.Unpin(); err != nil {
			log.Warn(err)
		}
	}

	return nil
}

func (bpo *bpfProgramObjects) pin(path string) error {
	var value reflect.Value

	if err := os.Mkdir(path + "map/", 0750); err != nil && !os.IsExist(err) {
		return err
	}

	// pin Maps
	value = reflect.ValueOf(bpo.CgroupSockObjects.CgroupSockMaps)
	if err := pinMaps(&value, path + "map/"); err != nil {
		return err
	}
	value = reflect.ValueOf(bpo.FilterObjects.FilterMaps)
	if err := pinMaps(&value, path + "map/"); err != nil {
		return err
	}
	value = reflect.ValueOf(bpo.ClusterObjects.ClusterMaps)
	if err := pinMaps(&value, path + "map/"); err != nil {
		return err
	}

	// pin Programs
	value = reflect.ValueOf(bpo.CgroupSockObjects.CgroupSockPrograms)
	if err := pinPrograms(&value, path); err != nil {
		return err
	}
	value = reflect.ValueOf(bpo.FilterObjects.FilterPrograms)
	if err := pinPrograms(&value, path); err != nil {
		return err
	}
	value = reflect.ValueOf(bpo.ClusterObjects.ClusterPrograms)
	if err := pinPrograms(&value, path); err != nil {
		return err
	}

	return nil
}

func (bpo *bpfProgramObjects) unpin(path string) error {
	var value reflect.Value

	// unpin Programs
	value = reflect.ValueOf(bpo.CgroupSockObjects.CgroupSockPrograms)
	if err := unpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(bpo.FilterObjects.FilterPrograms)
	if err := unpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(bpo.ClusterObjects.ClusterPrograms)
	if err := unpinPrograms(&value); err != nil {
		return err
	}

	// unpin Maps
	value = reflect.ValueOf(bpo.CgroupSockObjects.CgroupSockMaps)
	if err := unpinMaps(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(bpo.FilterObjects.FilterMaps)
	if err := unpinMaps(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(bpo.ClusterObjects.ClusterMaps)
	if err := unpinMaps(&value); err != nil {
		return err
	}

	if err := os.Remove(path + "map/"); err != nil {
		return err
	}

	return nil
}

func (bpo *bpfProgramObjects) close() error {
	if err := bpo.CgroupSockObjects.Close(); err != nil {
		return err
	}
	if err := bpo.FilterObjects.Close(); err != nil {
		return err
	}
	if err := bpo.ClusterObjects.Close(); err != nil {
		return err
	}

	return nil
}

func (bpo *bpfProgramObjects) load() error {
	if err := LoadCgroupSockObjects(&bpo.CgroupSockObjects, nil); err != nil {
		return err
	}
	if err := LoadFilterObjects(&bpo.FilterObjects, nil); err != nil {
		return err
	}
	if err := LoadClusterObjects(&bpo.ClusterObjects, nil); err != nil {
		return err
	}

	return nil
}

func Load(info *BpfInfo) (*BpfObject, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	obj := &BpfObject{}
	obj.info = *info
	obj.info.AttachType = ebpf.AttachCGroupInet4Connect

	err := obj.progObjs.load()

	return obj, err
}

func (obj *BpfObject) Attach() error {
	if err := obj.progObjs.pin(obj.info.BpffsPath); err != nil {
		return err
	}

	cgopt := link.CgroupOptions {
		Path:		obj.info.Cgroup2Path,
		Attach:		obj.info.AttachType,
		Program:	obj.progObjs.CgroupSockObjects.Sock4Connect,
	}
	lk, err := link.AttachCgroup(cgopt)
	if err != nil {
		return err
	}
	obj.link = lk

	return nil
}

func (obj *BpfObject) Detach() error {
	if err := obj.progObjs.close(); err != nil {
		return err
	}
	if err := obj.progObjs.unpin(obj.info.BpffsPath); err != nil {
		return err
	}

	return obj.link.Close()
}

func Test() error {
	spec, err := LoadCgroupSock()
	if err != nil {
		return err
	}
	log.Debug("spec: ", spec)

	p := spec.Programs["sock4_connect"]
	log.Debug("prog: ", p)

	m := spec.Maps["tail_call_prog"]
	log.Debug("map: ", m)

	return nil
}