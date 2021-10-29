/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

package bpf

// #cgo CFLAGS: -I../../bpf/include
// #include "tail_call.h"
import "C"

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
	Cgroup2Path	string
	BpffsPath	string
	mapPath		string
	Type		ebpf.ProgramType
	AttachType	ebpf.AttachType
}
type bpfSocketConnect struct {
	info 		BpfInfo
	link		link.Link
	CgroupSockObjects
	FilterObjects
	ClusterObjects
}
type BpfObject struct {
	SockConn	*bpfSocketConnect
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

func NewSocketConnect(i *BpfInfo) (*bpfSocketConnect, error) {
	sc := &bpfSocketConnect {
		info: *i,
	}

	if _, err := os.Stat(sc.info.Cgroup2Path); err != nil {
		return nil, err
	}
	if _, err := os.Stat(sc.info.BpffsPath); err != nil {
		return nil, err
	}

	sc.info.BpffsPath += "socket_connect/"
	sc.info.mapPath = sc.info.BpffsPath + "map/"
	if err := os.MkdirAll(sc.info.mapPath, 0750); err != nil && !os.IsExist(err) {
		return nil, err
	}

	return sc, nil
}

func setMapPinType(spec *ebpf.CollectionSpec, pinType ebpf.PinType) {
	for _, v := range spec.Maps {
		v.Pinning = pinType
	}
}

func setProgBpfType(spec *ebpf.CollectionSpec, typ ebpf.ProgramType, atyp ebpf.AttachType) {
	for _, v := range spec.Programs {
		v.Type = typ
		v.AttachType = atyp
	}
}

func (sc *bpfSocketConnect) loadCgroupSockObjects() (*ebpf.CollectionSpec, error) {
	var (
		err		error
		spec	*ebpf.CollectionSpec
		opts 	ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.info.mapPath

	if spec, err = LoadCgroupSock(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sc.CgroupSockObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sc.CgroupSockObjects.CgroupSockPrograms)
	if err = pinPrograms(&value, sc.info.BpffsPath); err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *bpfSocketConnect) loadFilterObjects() (*ebpf.CollectionSpec, error) {
	var (
		err		error
		spec	*ebpf.CollectionSpec
		opts 	ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.info.mapPath

	if spec, err = LoadFilter(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	setProgBpfType(spec, sc.info.Type, sc.info.AttachType)
	if err = spec.LoadAndAssign(&sc.FilterObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sc.FilterObjects.FilterPrograms)
	if err = pinPrograms(&value, sc.info.BpffsPath); err != nil {
		return nil, err
	}

	err = sc.FilterObjects.FilterMaps.TailCallProg.Update(
		uint32(C.KMESH_TAIL_CALL_FILTER_CHAIN),
		uint32(sc.FilterObjects.FilterPrograms.FilterChainManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return nil, err
	}

	err = sc.FilterObjects.FilterMaps.TailCallProg.Update(
		uint32(C.KMESH_TAIL_CALL_FILTER),
		uint32(sc.FilterObjects.FilterPrograms.FilterManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *bpfSocketConnect) loadClusterObjects() (*ebpf.CollectionSpec, error) {
	var (
		err		error
		spec	*ebpf.CollectionSpec
		opts 	ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.info.mapPath

	if spec, err = LoadCluster(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	setProgBpfType(spec, sc.info.Type, sc.info.AttachType)
	if err = spec.LoadAndAssign(&sc.ClusterObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sc.ClusterObjects.ClusterPrograms)
	if err = pinPrograms(&value, sc.info.BpffsPath); err != nil {
		return nil, err
	}

	err = sc.ClusterObjects.ClusterMaps.TailCallProg.Update(
		uint32(C.KMESH_TAIL_CALL_CLUSTER),
		uint32(sc.ClusterObjects.ClusterPrograms.ClusterManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *bpfSocketConnect) load() error {
	spec, err := sc.loadCgroupSockObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["sock_connect4"]
	sc.info.Type = prog.Type
	sc.info.AttachType = prog.AttachType

	if _, err := sc.loadFilterObjects(); err != nil {
		return err
	}
	if _, err := sc.loadClusterObjects(); err != nil {
		return err
	}

	return nil
}

func (sc *bpfSocketConnect) attach() error {
	cgopt := link.CgroupOptions {
		Path:		sc.info.Cgroup2Path,
		Attach:		sc.info.AttachType,
		Program:	sc.CgroupSockObjects.SockConnect4,
	}

	lk, err := link.AttachCgroup(cgopt)
	if err != nil {
		return err
	}
	sc.link = lk

	return nil
}

func (sc *bpfSocketConnect) close() error {
	if err := sc.CgroupSockObjects.Close(); err != nil {
		return err
	}
	if err := sc.FilterObjects.Close(); err != nil {
		return err
	}
	if err := sc.ClusterObjects.Close(); err != nil {
		return err
	}

	return nil
}

func (sc *bpfSocketConnect) detach() error {
	var value reflect.Value

	if err := sc.close(); err != nil {
		return err
	}

	value = reflect.ValueOf(sc.CgroupSockObjects.CgroupSockPrograms)
	if err := unpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(sc.CgroupSockObjects.CgroupSockMaps)
	if err := unpinMaps(&value); err != nil {
		return err
	}

	if err := os.RemoveAll(sc.info.BpffsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if sc.link != nil {
		return sc.link.Close()
	}
	return nil
}

func Load(info *BpfInfo) (*BpfObject, error) {
	var (
		err error
	)
	obj := &BpfObject{}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	if obj.SockConn, err = NewSocketConnect(info); err != nil {
		return nil, err
	}

	err = obj.SockConn.load()
	return obj, err
}

func (obj *BpfObject) Attach() error {
	return obj.SockConn.attach()
}

func (obj *BpfObject) Detach() error {
	return obj.SockConn.detach()
}
