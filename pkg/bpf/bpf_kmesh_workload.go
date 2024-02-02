/*
 * Copyright 2024 The Kmesh Authors.
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

 * Author: kwb0523
 * Create: 2024-01-08
 */

package bpf

// #cgo pkg-config: bpf api-v2-c
// #include "kmesh/include/kmesh_common.h"

import (
	"os"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"kmesh.net/kmesh/bpf/kmesh/bpf2go"
)

type BpfSockConnWorkload struct {
	Info BpfInfo
	Link link.Link
	bpf2go.KmeshCgroupSockWorkloadObjects
}

func (sc *BpfSockConnWorkload) NewBpf(cfg *Config) error {
	sc.Info.Config = *cfg
	sc.Info.MapPath = sc.Info.BpfFsPath + "/bpf_kmesh_workload/map/"
	sc.Info.BpfFsPath += "/bpf_kmesh_workload/sockconn/"

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

func (sc *BpfSockConnWorkload) loadKmeshSockConnObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.Info.MapPath
	opts.Programs.LogSize = sc.Info.BpfVerifyLogSize

	spec, err = bpf2go.LoadKmeshCgroupSockWorkload()

	if err != nil || spec == nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sc.KmeshCgroupSockWorkloadObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sc.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadPrograms)
	if err = pinPrograms(&value, sc.Info.BpfFsPath); err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *BpfSockConnWorkload) LoadSockConn() error {
	/* load kmesh sockops main bpf prog */
	spec, err := sc.loadKmeshSockConnObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["cgroup_connect4_prog"]
	sc.Info.Type = prog.Type
	sc.Info.AttachType = prog.AttachType

	return nil
}

func (sc *BpfSockConnWorkload) close() error {
	if err := sc.KmeshCgroupSockWorkloadObjects.Close(); err != nil {
		return err
	}
	return nil
}

func (sc *BpfSockConnWorkload) Attach() error {
	cgopt := link.CgroupOptions{
		Path:    sc.Info.Cgroup2Path,
		Attach:  sc.Info.AttachType,
		Program: sc.KmeshCgroupSockWorkloadObjects.CgroupConnect4Prog,
	}

	lk, err := link.AttachCgroup(cgopt)
	if err != nil {
		return err
	}
	sc.Link = lk

	return nil
}

func (sc *BpfSockConnWorkload) Detach() error {
	var value reflect.Value

	if err := sc.close(); err != nil {
		return err
	}

	value = reflect.ValueOf(sc.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadPrograms)
	if err := unpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(sc.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps)
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
