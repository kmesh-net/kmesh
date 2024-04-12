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
	"fmt"
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

type BpfSockOpsWorkload struct {
	Info BpfInfo
	Link link.Link
	bpf2go.KmeshSockopsWorkloadObjects
}

func (so *BpfSockOpsWorkload) NewBpf(cfg *Config) error {
	so.Info.Config = *cfg
	so.Info.MapPath = so.Info.BpfFsPath + "/bpf_kmesh_workload/map/"
	so.Info.BpfFsPath += "/bpf_kmesh_workload/sockops/"

	if err := os.MkdirAll(so.Info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(so.Info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (so *BpfSockOpsWorkload) loadKmeshSockopsObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)

	opts.Maps.PinPath = so.Info.MapPath
	opts.Programs.LogSize = so.Info.BpfVerifyLogSize

	spec, err = bpf2go.LoadKmeshSockopsWorkload()
	if err != nil {
		return nil, err
	}
	if spec == nil {
		return nil, fmt.Errorf("error: loadKmeshSockopsObjects() spec is nil")
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&so.KmeshSockopsWorkloadObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadPrograms)
	if err = pinPrograms(&value, so.Info.BpfFsPath); err != nil {
		return nil, err
	}

	return spec, nil
}
func (so *BpfSockOpsWorkload) LoadSockOps() error {
	/* load kmesh sockops main bpf prog*/
	spec, err := so.loadKmeshSockopsObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["socket_migration"]
	so.Info.Type = prog.Type
	so.Info.AttachType = prog.AttachType

	return nil
}

func (so *BpfSockOpsWorkload) Attach() error {
	cgopt := link.CgroupOptions{
		Path:    so.Info.Cgroup2Path,
		Attach:  so.Info.AttachType,
		Program: so.KmeshSockopsWorkloadObjects.RecordTuple,
	}

	lk, err := link.AttachCgroup(cgopt)
	if err != nil {
		return err
	}
	so.Link = lk
	return nil
}

func (so *BpfSockOpsWorkload) close() error {
	if err := so.KmeshSockopsWorkloadObjects.Close(); err != nil {
		return err
	}
	return nil
}

func (so *BpfSockOpsWorkload) Detach() error {
	if err := so.close(); err != nil {
		return err
	}

	program_value := reflect.ValueOf(so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadPrograms)
	if err := unpinPrograms(&program_value); err != nil {
		return err
	}

	map_value := reflect.ValueOf(so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadMaps)
	if err := unpinMaps(&map_value); err != nil {
		return err
	}

	if err := os.RemoveAll(so.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if so.Link != nil {
		return so.Link.Close()
	}
	return nil
}

type BpfXdpAuthWorkload struct {
	Info BpfInfo
	Link link.Link
	bpf2go.KmeshXDPAuthObjects
}

func (xa *BpfXdpAuthWorkload) NewBpf(cfg *Config) error {
	xa.Info.Config = *cfg
	xa.Info.MapPath = xa.Info.BpfFsPath + "/bpf_kmesh_workload/map/"
	xa.Info.BpfFsPath += "/bpf_kmesh_workload/xdpauth/"

	if err := os.MkdirAll(xa.Info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(xa.Info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (xa *BpfXdpAuthWorkload) loadKmeshXdpAuthObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)

	opts.Maps.PinPath = xa.Info.MapPath
	opts.Programs.LogSize = xa.Info.BpfVerifyLogSize

	spec, err = bpf2go.LoadKmeshXDPAuth()
	if err != nil {
		return nil, err
	}
	if spec == nil {
		return nil, fmt.Errorf("error: loadKmeshXdpAuthObjects() spec is nil")
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&xa.KmeshXDPAuthObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(xa.KmeshXDPAuthObjects.KmeshXDPAuthPrograms)
	if err = pinPrograms(&value, xa.Info.BpfFsPath); err != nil {
		return nil, err
	}

	return spec, nil
}

func (xa *BpfXdpAuthWorkload) LoadXdpAuth() error {
	spec, err := xa.loadKmeshXdpAuthObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["xdp_auth_handler"]
	xa.Info.Type = prog.Type
	xa.Info.AttachType = prog.AttachType

	return nil
}

func (xa *BpfXdpAuthWorkload) Close() error {
	if err := xa.KmeshXDPAuthObjects.Close(); err != nil {
		return err
	}
	progVal := reflect.ValueOf(xa.KmeshXDPAuthObjects.KmeshXDPAuthPrograms)
	if err := unpinPrograms(&progVal); err != nil {
		return err
	}

	mapVal := reflect.ValueOf(xa.KmeshXDPAuthObjects.KmeshXDPAuthMaps)
	if err := unpinMaps(&mapVal); err != nil {
		return err
	}

	if err := os.RemoveAll(xa.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if xa.Link != nil {
		return xa.Link.Close()
	}
	return nil
}
