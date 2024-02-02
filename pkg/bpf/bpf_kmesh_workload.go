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

	if err != nil || spec == nil {
		return nil, err
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

	prog := spec.Programs["sockops_prog"]
	so.Info.Type = prog.Type
	so.Info.AttachType = prog.AttachType

	return nil
}

func (so *BpfSockOpsWorkload) Attach() error {
	cgopt := link.CgroupOptions{
		Path:    so.Info.Cgroup2Path,
		Attach:  so.Info.AttachType,
		Program: so.KmeshSockopsWorkloadObjects.SockopsProg,
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
	var value reflect.Value

	if err := so.close(); err != nil {
		return err
	}

	value = reflect.ValueOf(so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadPrograms)
	if err := unpinPrograms(&value); err != nil {
		return err
	}

	value = reflect.ValueOf(so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadMaps)
	if err := unpinMaps(&value); err != nil {
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

func (so *BpfSockOpsWorkload) GetSockMapFD() int {
	return so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadMaps.MapOfKmeshHashmap.FD()
}

type BpfSendMsgWorkload struct {
	Info     BpfInfo
	AttachFD int
	bpf2go.KmeshSendmsgObjects
}

func (sm *BpfSendMsgWorkload) NewBpf(cfg *Config) error {
	sm.Info.Config = *cfg
	sm.Info.MapPath = sm.Info.BpfFsPath + "/bpf_kmesh_workload/map/"
	sm.Info.BpfFsPath += "/bpf_kmesh_workload/sendmsg/"

	if err := os.MkdirAll(sm.Info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(sm.Info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (sm *BpfSendMsgWorkload) loadKmeshSendmsgObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sm.Info.MapPath
	opts.Programs.LogSize = sm.Info.BpfVerifyLogSize

	spec, err = bpf2go.LoadKmeshSendmsg()

	if err != nil || spec == nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sm.KmeshSendmsgObjects, &opts); err != nil {
		return nil, err
	}

	if err = spec.LoadAndAssign(&sm.KmeshSendmsgObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sm.KmeshSendmsgObjects.KmeshSendmsgPrograms)
	if err = pinPrograms(&value, sm.Info.BpfFsPath); err != nil {
		return nil, err
	}
	return spec, nil
}

func (sm *BpfSendMsgWorkload) LoadSendMsg() error {
	/* load kmesh sendmsg main bpf prog */
	spec, err := sm.loadKmeshSendmsgObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["sendmsg"]
	sm.Info.Type = prog.Type
	sm.Info.AttachType = prog.AttachType
	return nil
}

func (sm *BpfSendMsgWorkload) Attach() error {
	// Use a program handle that cannot be closed by the caller
	clone, err := sm.KmeshSendmsgObjects.KmeshSendmsgPrograms.Sendmsg.Clone()
	sm.AttachFD = ObjWorkload.KmeshWorkload.SockOps.GetSockMapFD()
	args := link.RawAttachProgramOptions{
		Target:  sm.AttachFD,
		Program: clone,
		Flags:   0,
		Attach:  ebpf.AttachSkMsgVerdict,
	}

	if err = link.RawAttachProgram(args); err != nil {
		return err
	}
	return nil
}

func (sm *BpfSendMsgWorkload) Detach() error {
	if sm.AttachFD > 0 {
		args := link.RawDetachProgramOptions{
			Target:  sm.AttachFD,
			Program: sm.KmeshSendmsgObjects.KmeshSendmsgPrograms.Sendmsg,
			Attach:  ebpf.AttachSkMsgVerdict,
		}

		if err := link.RawDetachProgram(args); err != nil {
			return err
		}
	}

	if err := sm.KmeshSendmsgObjects.Close(); err != nil {
		return err
	}
	return nil
}

type BpfSkbVerdictWorkload struct {
	Info     BpfInfo
	AttachFD int
	bpf2go.KmeshSkbVerdictObjects
}

func (sv *BpfSkbVerdictWorkload) NewBpf(cfg *Config) error {
	sv.Info.Config = *cfg
	sv.Info.MapPath = sv.Info.BpfFsPath + "/bpf_kmesh_workload/map/"
	sv.Info.BpfFsPath += "/bpf_kmesh_workload/skbverdict"

	if err := os.MkdirAll(sv.Info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(sv.Info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (sv *BpfSkbVerdictWorkload) loadKmeshSkbVerdictObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sv.Info.MapPath
	opts.Programs.LogSize = sv.Info.BpfVerifyLogSize

	spec, err = bpf2go.LoadKmeshSkbVerdict()

	if err != nil || spec == nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sv.KmeshSkbVerdictObjects, &opts); err != nil {
		return nil, err
	}

	if err = spec.LoadAndAssign(&sv.KmeshSkbVerdictObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sv.KmeshSkbVerdictObjects.KmeshSkbVerdictPrograms)
	if err = pinPrograms(&value, sv.Info.BpfFsPath); err != nil {
		return nil, err
	}
	return spec, nil
}

func (sv *BpfSkbVerdictWorkload) LoadSkbVerdict() error {
	/* load kmesh verdict main bpf prog */
	spec, err := sv.loadKmeshSkbVerdictObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["verdict"]
	sv.Info.Type = prog.Type
	sv.Info.AttachType = prog.AttachType
	return nil
}

func (sv *BpfSkbVerdictWorkload) Attach() error {
	// Use a program handle that cannot be closed by the caller
	clone, err := sv.KmeshSkbVerdictObjects.KmeshSkbVerdictPrograms.Verdict.Clone()
	sv.AttachFD = ObjWorkload.KmeshWorkload.SockOps.GetSockMapFD()
	args := link.RawAttachProgramOptions{
		Target:  sv.AttachFD,
		Program: clone,
		Flags:   0,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	}

	if err = link.RawAttachProgram(args); err != nil {
		return err
	}
	return nil
}

func (sv *BpfSkbVerdictWorkload) Detach() error {
	if sv.AttachFD > 0 {
		args := link.RawDetachProgramOptions{
			Target:  sv.AttachFD,
			program: sv.KmeshSkbVerdictObjects.KmeshSkbVerdictPrograms.Verdict,
			Attach:  ebpf.AttachSkSKBStreamVerdict,
		}

		if err := link.RawDetachProgram(args); err != nil {
			return err
		}
	}

	if err := sv.KmeshSkbVerdictObjects.Close(); err != nil {
		return err
	}
	return nil
}
