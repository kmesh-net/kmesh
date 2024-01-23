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

 * Author: lec-bit
 * Create: 2023-11-02
 */

package bpf

// #cgo pkg-config: bpf api-v2-c
// #include "kmesh/include/kmesh_common.h"
import "C"
import (
	"os"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"kmesh.net/kmesh/bpf/kmesh/bpf2go"
)

var KMESH_TAIL_CALL_LISTENER = uint32(C.KMESH_TAIL_CALL_LISTENER)
var KMESH_TAIL_CALL_FILTER_CHAIN = uint32(C.KMESH_TAIL_CALL_FILTER_CHAIN)
var KMESH_TAIL_CALL_FILTER = uint32(C.KMESH_TAIL_CALL_FILTER)
var KMESH_TAIL_CALL_ROUTER = uint32(C.KMESH_TAIL_CALL_ROUTER)
var KMESH_TAIL_CALL_CLUSTER = uint32(C.KMESH_TAIL_CALL_CLUSTER)
var KMESH_TAIL_CALL_ROUTER_CONFIG = uint32(C.KMESH_TAIL_CALL_ROUTER_CONFIG)
var BPF_INNER_MAP_DATA_LEN = uint32(C.BPF_INNER_MAP_DATA_LEN)

type BpfSockConn struct {
	Info BpfInfo
	Link link.Link
	bpf2go.KmeshCgroupSockObjects
}

func (sc *BpfSockConn) NewBpf(cfg *Config) error {
	sc.Info.Config = *cfg
	sc.Info.MapPath = sc.Info.BpfFsPath + "/bpf_kmesh/map/"
	sc.Info.BpfFsPath += "/bpf_kmesh/sockconn/"

	if err := os.MkdirAll(sc.Info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(sc.Info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func SetInnerMap(spec *ebpf.CollectionSpec) {
	var (
		InnerMapKeySize    uint32 = 4
		InnerMapDataLength uint32 = BPF_INNER_MAP_DATA_LEN
		InnerMapMaxEntries uint32 = 1
	)
	for _, v := range spec.Maps {
		if v.Name == "outer_map" {
			v.InnerMap = &ebpf.MapSpec{
				Type:       ebpf.Array,
				KeySize:    InnerMapKeySize,
				ValueSize:  InnerMapDataLength, // C.BPF_INNER_MAP_DATA_LEN
				MaxEntries: InnerMapMaxEntries,
			}
		}
	}
}

func (sc *BpfSockConn) loadKmeshSockConnObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.Info.MapPath
	opts.Programs.LogSize = sc.Info.BpfVerifyLogSize

	spec, err = bpf2go.LoadKmeshCgroupSock()

	if err != nil || spec == nil {
		return nil, err
	}

	SetInnerMap(spec)
	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sc.KmeshCgroupSockObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sc.KmeshCgroupSockObjects.KmeshCgroupSockPrograms)
	if err = pinPrograms(&value, sc.Info.BpfFsPath); err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *BpfSockConn) LoadSockConn() error {
	/* load kmesh sockops main bpf prog */
	spec, err := sc.loadKmeshSockConnObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["cgroup_connect4_prog"]
	sc.Info.Type = prog.Type
	sc.Info.AttachType = prog.AttachType

	// update tail call prog
	err = sc.KmeshTailCallProg.Update(
		uint32(KMESH_TAIL_CALL_FILTER_CHAIN),
		uint32(sc.FilterChainManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return err
	}

	err = sc.KmeshTailCallProg.Update(
		uint32(KMESH_TAIL_CALL_FILTER),
		uint32(sc.FilterManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return err
	}

	err = sc.KmeshTailCallProg.Update(
		uint32(KMESH_TAIL_CALL_CLUSTER),
		uint32(sc.ClusterManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return err
	}

	return nil
}

func (sc *BpfSockConn) close() error {
	if err := sc.KmeshCgroupSockObjects.Close(); err != nil {
		return err
	}
	return nil
}

func (sc *BpfSockConn) Attach() error {
	cgopt := link.CgroupOptions{
		Path:    sc.Info.Cgroup2Path,
		Attach:  sc.Info.AttachType,
		Program: sc.KmeshCgroupSockObjects.CgroupConnect4Prog,
	}

	lk, err := link.AttachCgroup(cgopt)
	if err != nil {
		return err
	}
	sc.Link = lk

	return nil
}

func (sc *BpfSockConn) Detach() error {
	var value reflect.Value

	if err := sc.close(); err != nil {
		return err
	}

	value = reflect.ValueOf(sc.KmeshCgroupSockObjects.KmeshCgroupSockPrograms)
	if err := unpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(sc.KmeshCgroupSockObjects.KmeshCgroupSockMaps)
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
