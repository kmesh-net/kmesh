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

// #cgo pkg-config: bpf api-v1-c
// #include "slb/tail_call.h"
import "C"
import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"openeuler.io/mesh/bpf/slb/bpf2go"
	"os"
	"reflect"
)

const pinName = "bpf_slb"

type BpfSlb struct {
	Info 		BpfInfo
	Link		link.Link
	bpf2go.CgroupSockObjects
	bpf2go.FilterObjects
	bpf2go.ClusterObjects
}

func NewBpfSlb(cfg *Config) (BpfSlb, error) {
	b := BpfSlb{}
	b.Info.Config = *cfg

	b.Info.BpfFsPath += "/" + pinName + "/"
	b.Info.MapPath = b.Info.BpfFsPath + "map/"
	if err := os.MkdirAll(b.Info.MapPath, 0750); err != nil && !os.IsExist(err) {
		return b, err
	}

	return b, nil
}

func (b *BpfSlb) loadCgroupSockObjects() (*ebpf.CollectionSpec, error) {
	var (
		err		error
		spec	*ebpf.CollectionSpec
		opts 	ebpf.CollectionOptions
	)
	opts.Maps.PinPath = b.Info.MapPath

	if spec, err = bpf2go.LoadCgroupSock(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&b.CgroupSockObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(b.CgroupSockObjects.CgroupSockPrograms)
	if err = pinPrograms(&value, b.Info.BpfFsPath); err != nil {
		return nil, err
	}

	return spec, nil
}

func (b *BpfSlb) loadFilterObjects() (*ebpf.CollectionSpec, error) {
	var (
		err		error
		spec	*ebpf.CollectionSpec
		opts 	ebpf.CollectionOptions
	)
	opts.Maps.PinPath = b.Info.MapPath

	if spec, err = bpf2go.LoadFilter(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	setProgBpfType(spec, b.Info.Type, b.Info.AttachType)
	if err = spec.LoadAndAssign(&b.FilterObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(b.FilterObjects.FilterPrograms)
	if err = pinPrograms(&value, b.Info.BpfFsPath); err != nil {
		return nil, err
	}

	err = b.FilterObjects.FilterMaps.TailCallProg.Update(
		uint32(C.KMESH_TAIL_CALL_FILTER_CHAIN),
		uint32(b.FilterObjects.FilterPrograms.FilterChainManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return nil, err
	}

	err = b.FilterObjects.FilterMaps.TailCallProg.Update(
		uint32(C.KMESH_TAIL_CALL_FILTER),
		uint32(b.FilterObjects.FilterPrograms.FilterManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return nil, err
	}

	return spec, nil
}

func (b *BpfSlb) loadClusterObjects() (*ebpf.CollectionSpec, error) {
	var (
		err		error
		spec	*ebpf.CollectionSpec
		opts 	ebpf.CollectionOptions
	)
	opts.Maps.PinPath = b.Info.MapPath

	if spec, err = bpf2go.LoadCluster(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	setProgBpfType(spec, b.Info.Type, b.Info.AttachType)
	if err = spec.LoadAndAssign(&b.ClusterObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(b.ClusterObjects.ClusterPrograms)
	if err = pinPrograms(&value, b.Info.BpfFsPath); err != nil {
		return nil, err
	}

	err = b.ClusterObjects.ClusterMaps.TailCallProg.Update(
		uint32(C.KMESH_TAIL_CALL_CLUSTER),
		uint32(b.ClusterObjects.ClusterPrograms.ClusterManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return nil, err
	}

	return spec, nil
}

func (b *BpfSlb) Load() error {
	spec, err := b.loadCgroupSockObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["sock_connect4"]
	b.Info.Type = prog.Type
	b.Info.AttachType = prog.AttachType

	if _, err := b.loadFilterObjects(); err != nil {
		return err
	}
	if _, err := b.loadClusterObjects(); err != nil {
		return err
	}

	return nil
}

func (b *BpfSlb) Attach() error {
	cgroupOpt := link.CgroupOptions {
		Path:    b.Info.Cgroup2Path,
		Attach:  b.Info.AttachType,
		Program: b.CgroupSockObjects.SockConnect4,
	}

	lk, err := link.AttachCgroup(cgroupOpt)
	if err != nil {
		return err
	}
	b.Link = lk

	return nil
}

func (b *BpfSlb) close() error {
	if err := b.CgroupSockObjects.Close(); err != nil {
		return err
	}
	if err := b.FilterObjects.Close(); err != nil {
		return err
	}
	if err := b.ClusterObjects.Close(); err != nil {
		return err
	}

	return nil
}

func (b *BpfSlb) Detach() error {
	var value reflect.Value

	if err := b.close(); err != nil {
		return err
	}

	value = reflect.ValueOf(b.CgroupSockObjects.CgroupSockPrograms)
	if err := unpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(b.CgroupSockObjects.CgroupSockMaps)
	if err := unpinMaps(&value); err != nil {
		return err
	}

	if err := os.RemoveAll(b.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if b.Link != nil {
		return b.Link.Close()
	}
	return nil
}
