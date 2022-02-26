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
 * Create: 2021-12-07
 */

package bpf

// #cgo pkg-config: api-v1-c bpf-kmesh
// #include "tail_call.h"
import "C"
import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"openeuler.io/mesh/bpf/slb/bpf2go"
	"os"
	"reflect"
)

type BpfSocketConnect struct {
	Info 		BpfInfo
	Link		link.Link
	bpf2go.CgroupSockObjects
	bpf2go.FilterObjects
	bpf2go.ClusterObjects
}

func NewSocketConnect(cfg *Config) (BpfSocketConnect, error) {
	sc := BpfSocketConnect {}
	sc.Info.Config = *cfg

	sc.Info.BpfFsPath += "/socket_connect/"
	sc.Info.MapPath = sc.Info.BpfFsPath + "map/"
	if err := os.MkdirAll(sc.Info.MapPath, 0750); err != nil && !os.IsExist(err) {
		return sc, err
	}

	return sc, nil
}

func (sc *BpfSocketConnect) loadCgroupSockObjects() (*ebpf.CollectionSpec, error) {
	var (
		err		error
		spec	*ebpf.CollectionSpec
		opts 	ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.Info.MapPath

	if spec, err = bpf2go.LoadCgroupSock(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sc.CgroupSockObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sc.CgroupSockObjects.CgroupSockPrograms)
	if err = pinPrograms(&value, sc.Info.BpfFsPath); err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *BpfSocketConnect) loadFilterObjects() (*ebpf.CollectionSpec, error) {
	var (
		err		error
		spec	*ebpf.CollectionSpec
		opts 	ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.Info.MapPath

	if spec, err = bpf2go.LoadFilter(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	setProgBpfType(spec, sc.Info.Type, sc.Info.AttachType)
	if err = spec.LoadAndAssign(&sc.FilterObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sc.FilterObjects.FilterPrograms)
	if err = pinPrograms(&value, sc.Info.BpfFsPath); err != nil {
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

func (sc *BpfSocketConnect) loadClusterObjects() (*ebpf.CollectionSpec, error) {
	var (
		err		error
		spec	*ebpf.CollectionSpec
		opts 	ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.Info.MapPath

	if spec, err = bpf2go.LoadCluster(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	setProgBpfType(spec, sc.Info.Type, sc.Info.AttachType)
	if err = spec.LoadAndAssign(&sc.ClusterObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sc.ClusterObjects.ClusterPrograms)
	if err = pinPrograms(&value, sc.Info.BpfFsPath); err != nil {
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

func (sc *BpfSocketConnect) Load() error {
	spec, err := sc.loadCgroupSockObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["sock_connect4"]
	sc.Info.Type = prog.Type
	sc.Info.AttachType = prog.AttachType

	if _, err := sc.loadFilterObjects(); err != nil {
		return err
	}
	if _, err := sc.loadClusterObjects(); err != nil {
		return err
	}

	return nil
}

func (sc *BpfSocketConnect) Attach() error {
	cgopt := link.CgroupOptions {
		Path:		sc.Info.Cgroup2Path,
		Attach:		sc.Info.AttachType,
		Program:	sc.CgroupSockObjects.SockConnect4,
	}

	lk, err := link.AttachCgroup(cgopt)
	if err != nil {
		return err
	}
	sc.Link = lk

	return nil
}

func (sc *BpfSocketConnect) close() error {
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

func (sc *BpfSocketConnect) Detach() error {
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

	if err := os.RemoveAll(sc.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if sc.Link != nil {
		return sc.Link.Close()
	}
	return nil
}
