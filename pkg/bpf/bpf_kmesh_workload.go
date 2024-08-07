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
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/cilium/coverbee"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"kmesh.net/kmesh/bpf/kmesh/bpf2go"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/constants"
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
	sc.Info.BpfVerifyLogSize = cfg.BpfVerifyLogSize
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
	opts.Programs.LogSize = sc.Info.BpfVerifyLogSize

	spec, err = bpf2go.LoadKmeshCgroupSockWorkload()

	if err != nil || spec == nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sc.KmeshCgroupSockWorkloadObjects, &opts); err != nil {
		return nil, err
	}

	if GetStartType() == Restart {
		return spec, nil
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

func (sc *BpfSockConnWorkload) Attach() error {
	var err error
	cgopt := link.CgroupOptions{
		Path:    sc.Info.Cgroup2Path,
		Attach:  sc.Info.AttachType,
		Program: sc.KmeshCgroupSockWorkloadObjects.CgroupConnect4Prog,
	}

	sc.Link, err = link.AttachCgroup(cgopt)
	if err != nil {
		return err
	}

	cgopt = link.CgroupOptions{
		Path:    sc.Info6.Cgroup2Path,
		Attach:  sc.Info6.AttachType,
		Program: sc.KmeshCgroupSockWorkloadObjects.CgroupConnect6Prog,
	}

	sc.Link6, err = link.AttachCgroup(cgopt)

	if GetStartType() == Restart {
		return err
	}

	if err := sc.Link.Pin(sc.Info.BpfFsPath + "sockconn_prog"); err != nil {
		return err
	}
	if err := sc.Link6.Pin(sc.Info.BpfFsPath + "sockconn6_prog"); err != nil {
		return err
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
	Coll *ebpf.Collection
}

func (so *BpfSockOpsWorkload) NewBpf(cfg *options.BpfConfig) error {
	so.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	so.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/sockops/"
	so.Info.BpfVerifyLogSize = cfg.BpfVerifyLogSize
	so.Info.Cgroup2Path = cfg.Cgroup2Path
	so.Info.EnableCoverage = cfg.EnableBpfCoverage

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
	// Log size too small can cause 'no space left on device' error in coverbee.InstrumentAndLoadCollection
	opts.Programs.LogSize = 1 << 26

	spec, err = bpf2go.LoadKmeshSockopsWorkload()
	if err != nil {
		return nil, err
	}
	if spec == nil {
		return nil, fmt.Errorf("error: loadKmeshSockopsObjects() spec is nil")
	}

	setMapPinType(spec, ebpf.PinByName)

	if !so.Info.EnableCoverage {
		if err = spec.LoadAndAssign(&so.KmeshSockopsWorkloadObjects, &opts); err != nil {
			return nil, err
		}

		if GetStartType() == Restart {
			return spec, nil
		}

		value := reflect.ValueOf(so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadPrograms)
		if err = pinPrograms(&value, so.Info.BpfFsPath); err != nil {
			return nil, err
		}
	} else {
		// Create parameter logWriter passed to coverbee InstrumentAndLoadCollection()
		logFile, err := os.Create("/kmesh/instrument-load.log")
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		defer logFile.Close()
		logWriter := bufio.NewWriter(logFile)
		defer logWriter.Flush()

		// Instrument and load ELF
		coll, cfg, err := coverbee.InstrumentAndLoadCollection(spec, opts, logWriter)
		if err != nil {
			return nil, fmt.Errorf("error while instrumenting and loading program: %w", err)
		}
		so.Coll = coll

		if GetStartType() == Restart {
			return spec, nil
		}

		// Pin programs
		for name, prog := range coll.Programs {
			if err = prog.Pin(filepath.Join(so.Info.BpfFsPath, name)); err != nil {
				return nil, fmt.Errorf("error pinning program '%s': %w", name, err)
			}
		}

		// Pin coverage map
		if err = coll.Maps["coverbee_covermap"].Pin(filepath.Join(so.Info.MapPath, "coverbee_covermap")); err != nil {
			return nil, fmt.Errorf("error pinning covermap: %w", err)
		}

		// Create block list and exported to a file
		blockList := coverbee.CFGToBlockList(cfg)
		blockListFile, err := os.Create("/kmesh/sockops-blocklist.json")
		if err != nil {
			return nil, fmt.Errorf("error create block-list: %w", err)
		}
		defer blockListFile.Close()

		if err = json.NewEncoder(blockListFile).Encode(&blockList); err != nil {
			return nil, fmt.Errorf("error encoding block-list: %w", err)
		}
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
		Path:   so.Info.Cgroup2Path,
		Attach: so.Info.AttachType,
	}
	if !so.Info.EnableCoverage {
		cgopt.Program = so.KmeshSockopsWorkloadObjects.SockopsProg
	} else {
		cgopt.Program = so.Coll.Programs["sockops_prog"]
	}

	lk, err := link.AttachCgroup(cgopt)
	if err != nil {
		return err
	}
	so.Link = lk

	if GetStartType() == Restart {
		return nil
	}

	if err := lk.Pin(so.Info.BpfFsPath + "cgroup_sockops_prog"); err != nil {
		return err
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
	if !so.Info.EnableCoverage {
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
	} else {
		// Generate coverage info before close
		// Load coverage map
		coverMap, err := ebpf.LoadPinnedMap(filepath.Join(so.Info.MapPath, "coverbee_covermap"), nil)
		if err != nil {
			return fmt.Errorf("load covermap pin: %w", err)
		}

		// Open block list file and get coverage info from coverage map
		blockList := make([][]coverbee.CoverBlock, 0)
		blockListPath, err := os.Open("/kmesh/sockops-blocklist.json")
		if err != nil {
			return fmt.Errorf("open block-list: %w", err)
		}

		if err = json.NewDecoder(blockListPath).Decode(&blockList); err != nil {
			return fmt.Errorf("decode block-list: %w", err)
		}

		if err = coverbee.ApplyCoverMapToBlockList(coverMap, blockList); err != nil {
			return fmt.Errorf("apply covermap: %w", err)
		}

		outBlocks, err := coverbee.SourceCodeInterpolation(blockList, nil)
		if err != nil {
			fmt.Printf("Warning error while interpolating using source files, falling back: %s", err.Error())
			outBlocks = blockList
		}

		output, err := os.Create("/kmesh/sockops-cov.html")
		if err != nil {
			return fmt.Errorf("error creating output file: %w", err)
		}
		defer output.Close()

		// Generate HTML coverage report
		if err = coverbee.BlockListToHTML(outBlocks, output, "count"); err != nil {
			return fmt.Errorf("block list to HTML: %w", err)
		}

		// Unpin progs and maps, then close the Collection
		for _, p := range so.Coll.Programs {
			if err := p.Unpin(); err != nil {
				return err
			}
		}
		for _, m := range so.Coll.Maps {
			if err := m.Unpin(); err != nil {
				return err
			}
		}
		so.Coll.Close()
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
	var fd int
	if !so.Info.EnableCoverage {
		fd = so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadMaps.MapOfKmeshSocket.FD()
	} else {
		fd = so.Coll.Maps["map_of_kmesh_socket"].FD()
	}
	return fd
}

func (so *BpfSockOpsWorkload) GetMapOfTuple() *ebpf.Map {
	var m *ebpf.Map
	if !so.Info.EnableCoverage {
		m = so.MapOfTuple
	} else {
		m = so.Coll.Maps["map_of_tuple"]
	}
	return m
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
	sm.Info.BpfVerifyLogSize = cfg.BpfVerifyLogSize
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
	opts.Programs.LogSize = sm.Info.BpfVerifyLogSize

	if spec, err = bpf2go.LoadKmeshSendmsg(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sm.KmeshSendmsgObjects, &opts); err != nil {
		return nil, err
	}

	if GetStartType() == Restart {
		return spec, nil
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
	xa.Info.BpfVerifyLogSize = cfg.BpfVerifyLogSize
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

	if GetStartType() == Restart {
		return spec, nil
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

	prog := spec.Programs[constants.XDP_PROG_NAME]
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
