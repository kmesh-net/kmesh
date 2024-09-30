/*
 * Copyright The Kmesh Authors.
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
 */

package bpf

// #cgo pkg-config: bpf api-v2-c
// #include "kmesh/include/kmesh_common.h"

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"kmesh.net/kmesh/bpf/kmesh/bpf2go"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/utils"
)

type BpfSockConnWorkload struct {
	Info  BpfInfo
	Link  link.Link
	Info6 BpfInfo
	Link6 link.Link
	bpf2go.KmeshCgroupSockWorkloadObjects
}

func (sc *BpfSockConnWorkload) NewBpf(cfg *options.BpfConfig) error {
	sc.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	sc.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/sockconn/"
	sc.Info.Cgroup2Path = cfg.Cgroup2Path
	sc.Info6 = sc.Info

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

	if utils.KernelVersionLowerThan5_13() {
		spec, err = bpf2go.LoadKmeshCgroupSockWorkloadCompat()
	} else {
		spec, err = bpf2go.LoadKmeshCgroupSockWorkload()
	}
	if err != nil {
		return nil, err
	}

	SetInnerMap(spec)
	setMapPinType(spec, ebpf.PinByName)
	// The real difference is in the .o file. The prog and map structures of the structure are exactly the same,
	// and the .o file has been loaded into the spec in bpf2go.LoadXX(),so when assigning spec to KmeshCgroupSockWorkloadObjects
	// here, there is no need to distinguish the type.
	if err = spec.LoadAndAssign(&sc.KmeshCgroupSockWorkloadObjects, &opts); err != nil {
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

	if err = sc.MapOfTailCallProg.Update(
		uint32(constants.TailCallConnect4Index),
		uint32(sc.CgroupConnect4Prog.FD()),
		ebpf.UpdateAny); err != nil {
		return err
	}

	prog = spec.Programs["cgroup_connect6_prog"]
	sc.Info6.Type = prog.Type
	sc.Info6.AttachType = prog.AttachType

	if err = sc.MapOfTailCallProg.Update(
		uint32(constants.TailCallConnect6Index),
		uint32(sc.CgroupConnect6Prog.FD()),
		ebpf.UpdateAny); err != nil {
		return err
	}
	return nil
}

func (sc *BpfSockConnWorkload) close() error {
	if err := sc.KmeshCgroupSockWorkloadObjects.Close(); err != nil {
		return err
	}
	return nil
}

func bpfProgUpdate(pinPath string, cgopt link.CgroupOptions) error {
	sclink, err := link.LoadPinnedLink(pinPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return err
	}
	if err := sclink.Update(cgopt.Program); err != nil {
		return fmt.Errorf("updating link %s failed: %w", pinPath, err)
	}
	return nil
}

func (sc *BpfSockConnWorkload) Attach() error {
	var err error
	cgopt4 := link.CgroupOptions{
		Path:    sc.Info.Cgroup2Path,
		Attach:  sc.Info.AttachType,
		Program: sc.KmeshCgroupSockWorkloadObjects.CgroupConnect4Prog,
	}

	cgopt6 := link.CgroupOptions{
		Path:    sc.Info6.Cgroup2Path,
		Attach:  sc.Info6.AttachType,
		Program: sc.KmeshCgroupSockWorkloadObjects.CgroupConnect6Prog,
	}

	pinPath4 := filepath.Join(sc.Info.BpfFsPath, "sockconn_prog")
	pinPath6 := filepath.Join(sc.Info.BpfFsPath, "sockconn6_prog")

	if GetStartType() == Restart {
		if err = bpfProgUpdate(pinPath4, cgopt4); err != nil {
			return err
		}

		if err = bpfProgUpdate(pinPath6, cgopt6); err != nil {
			return err
		}
	} else {
		sc.Link, err = link.AttachCgroup(cgopt4)
		if err != nil {
			return err
		}

		if err := sc.Link.Pin(pinPath4); err != nil {
			return err
		}

		sc.Link6, err = link.AttachCgroup(cgopt6)
		if err != nil {
			return err
		}

		if err := sc.Link6.Pin(pinPath6); err != nil {
			return err
		}
	}

	return err
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

	if err := os.RemoveAll(sc.Info6.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if sc.Link6 != nil {
		return sc.Link6.Close()
	}
	return nil
}

type BpfSockOpsWorkload struct {
	Info BpfInfo
	Link link.Link
	bpf2go.KmeshSockopsWorkloadObjects
}

func (so *BpfSockOpsWorkload) NewBpf(cfg *options.BpfConfig) error {
	so.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	so.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/sockops/"
	so.Info.Cgroup2Path = cfg.Cgroup2Path

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

	if utils.KernelVersionLowerThan5_13() {
		spec, err = bpf2go.LoadKmeshSockopsWorkloadCompat()
	} else {
		spec, err = bpf2go.LoadKmeshSockopsWorkload()
	}
	if err != nil {
		return nil, err
	}

	SetInnerMap(spec)
	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&so.KmeshSockopsWorkloadObjects, &opts); err != nil {
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
	pinPath := filepath.Join(so.Info.BpfFsPath, "cgroup_sockops_prog")

	if GetStartType() == Restart {
		if err := bpfProgUpdate(pinPath, cgopt); err != nil {
			return err
		}
	} else {
		lk, err := link.AttachCgroup(cgopt)
		if err != nil {
			return err
		}
		so.Link = lk

		if err := lk.Pin(pinPath); err != nil {
			return err
		}
	}

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

func (so *BpfSockOpsWorkload) GetSockMapFD() int {
	return so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadMaps.MapOfKmeshSocket.FD()
}

type BpfSendMsgWorkload struct {
	Info     BpfInfo
	AttachFD int
	bpf2go.KmeshSendmsgObjects

	sockOpsWorkloadObj *BpfSockOpsWorkload
}

func (sm *BpfSendMsgWorkload) NewBpf(cfg *options.BpfConfig, sockOpsWorkloadObj *BpfSockOpsWorkload) error {
	sm.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	sm.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/sendmsg/"
	sm.Info.Cgroup2Path = cfg.Cgroup2Path
	sm.sockOpsWorkloadObj = sockOpsWorkloadObj

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

	if utils.KernelVersionLowerThan5_13() {
		spec, err = bpf2go.LoadKmeshSendmsgCompat()
	} else {
		spec, err = bpf2go.LoadKmeshSendmsg()
	}
	if err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sm.KmeshSendmsgObjects, &opts); err != nil {
		return nil, err
	}

	// bpflink for sk_msg is supported in kernel 6.13, so we update sendmsg manually here
	// sendmsg ebpf prog is mounted on sockmap and processed for each socket.
	// It has the following characteristics:
	// 1. Multiple sk_msg ebpf prog can exist at the same time
	// 2. If the old sk_msg ebpf program is not pinned, it will wait until all
	// sockets on the old sk_msg ebpf prog are disconnected before automatically detaching.
	// Therefore, the following methods are used to achieve seamless replacement
	// 1) loading new sk_msg prog
	// 2) unpin old sk_msg prog: If sockmap is deleted, sk_msg will also be cleaned up
	// 3) pin new sk_msg prog
	// 4) attach new sk_msg prog(in SendMsg.Attach): Replace the old sk_msg prog
	if GetStartType() == Restart {
		pinPath := filepath.Join(sm.Info.BpfFsPath, "sendmsg_prog")
		oldSkMsg, err := ebpf.LoadPinnedProgram(pinPath, nil)
		if err != nil {
			log.Errorf("LoadPinnedProgram failed:%v", err)
			return nil, err
		}

		if err = oldSkMsg.Unpin(); err != nil {
			return nil, err
		}
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

	prog := spec.Programs["sendmsg_prog"]
	sm.Info.Type = prog.Type
	sm.Info.AttachType = prog.AttachType
	return nil
}

func (sm *BpfSendMsgWorkload) Attach() error {
	// Use a program handle that cannot be closed by the caller
	clone, err := sm.KmeshSendmsgObjects.KmeshSendmsgPrograms.SendmsgProg.Clone()
	if err != nil {
		return err
	}

	sm.AttachFD = sm.sockOpsWorkloadObj.GetSockMapFD()
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
			Program: sm.KmeshSendmsgObjects.KmeshSendmsgPrograms.SendmsgProg,
			Attach:  ebpf.AttachSkMsgVerdict,
		}

		if err := link.RawDetachProgram(args); err != nil {
			return err
		}
	}

	program_value := reflect.ValueOf(sm.KmeshSendmsgObjects.KmeshSendmsgPrograms)
	if err := unpinPrograms(&program_value); err != nil {
		return err
	}

	if err := os.RemoveAll(sm.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if err := sm.KmeshSendmsgObjects.Close(); err != nil {
		return err
	}
	return nil
}

type BpfXdpAuthWorkload struct {
	Info BpfInfo
	Link link.Link
	bpf2go.KmeshXDPAuthObjects
}

func (xa *BpfXdpAuthWorkload) NewBpf(cfg *options.BpfConfig) error {
	xa.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	xa.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/xdpauth/"
	xa.Info.Cgroup2Path = cfg.Cgroup2Path

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

	if utils.KernelVersionLowerThan5_13() {
		spec, err = bpf2go.LoadKmeshXDPAuthCompat()
	} else {
		spec, err = bpf2go.LoadKmeshXDPAuth()
	}
	if err != nil {
		return nil, err
	}

	SetInnerMap(spec)
	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&xa.KmeshXDPAuthObjects, &opts); err != nil {
		return nil, err
	}

	return spec, nil
}

func (xa *BpfXdpAuthWorkload) LoadXdpAuth() error {
	spec, err := xa.loadKmeshXdpAuthObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs[constants.XDP_PROG_NAME]
	xa.Info.Type = prog.Type
	xa.Info.AttachType = prog.AttachType

	if err = xa.MapOfTailCallProgForXdp.Update(
		uint32(constants.TailCallDstPortMatch),
		uint32(xa.MatchDstPorts.FD()),
		ebpf.UpdateAny); err != nil {
		return err
	}

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
