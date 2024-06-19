//go:build enhanced
// +build enhanced

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

 * Author: nlgwcy
 * Create: 2022-02-26
 */

package bpf

import (
	"os"
	"reflect"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"kmesh.net/kmesh/bpf/kmesh/bpf2go"
	"kmesh.net/kmesh/daemon/options"
)

type BpfTracePoint struct {
	Info BpfInfo
	Link link.Link
	bpf2go.KmeshTracePointObjects
}

type BpfSockOps struct {
	Info BpfInfo
	Link link.Link
	bpf2go.KmeshSockopsObjects
}

type BpfKmesh struct {
	TracePoint BpfTracePoint
	SockConn   BpfSockConn
	SockOps    BpfSockOps
}

func (sc *BpfTracePoint) NewBpf(cfg *options.BpfConfig) {
	sc.Info.MapPath = cfg.BpfFsPath
	sc.Info.BpfFsPath = cfg.BpfFsPath
	sc.Info.BpfVerifyLogSize = cfg.BpfVerifyLogSize
	sc.Info.Cgroup2Path = cfg.Cgroup2Path
}

func (sc *BpfSockOps) NewBpf(cfg *options.BpfConfig) error {
	sc.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh/map/"
	sc.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh/sockops/"
	sc.Info.BpfVerifyLogSize = cfg.BpfVerifyLogSize
	sc.Info.Cgroup2Path = cfg.Cgroup2Path

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

func NewBpfKmesh(cfg *options.BpfConfig) (*BpfKmesh, error) {
	var err error

	sc := &BpfKmesh{}

	sc.TracePoint.NewBpf(cfg)

	if err = sc.SockOps.NewBpf(cfg); err != nil {
		return sc, err
	}

	if err = sc.SockConn.NewBpf(cfg); err != nil {
		return sc, err
	}
	return sc, nil
}

func (sc *BpfTracePoint) loadKmeshTracePointObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Programs.LogSize = sc.Info.BpfVerifyLogSize

	spec, err = bpf2go.LoadKmeshTracePoint()
	if err != nil || spec == nil {
		return nil, err
	}

	for _, v := range spec.Programs {
		if v.Name == "connect_ret" {
			v.Type = ebpf.RawTracepointWritable
		}
	}

	if err = spec.LoadAndAssign(&sc.KmeshTracePointObjects, &opts); err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *BpfTracePoint) LoadTracePoint() error {
	if _, err := sc.loadKmeshTracePointObjects(); err != nil {
		return err
	}
	return nil
}

func (sc *BpfSockOps) loadKmeshSockopsObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.Info.MapPath
	opts.Programs.LogSize = sc.Info.BpfVerifyLogSize

	spec, err = bpf2go.LoadKmeshSockops()

	if err != nil || spec == nil {
		return nil, err
	}

	SetInnerMap(spec)
	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sc.KmeshSockopsObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sc.KmeshSockopsObjects.KmeshSockopsPrograms)
	if err = pinPrograms(&value, sc.Info.BpfFsPath); err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *BpfSockOps) loadKmeshFilterObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.Info.MapPath
	opts.Programs.LogSize = sc.Info.BpfVerifyLogSize

	err = sc.KmeshTailCallProg.Update(
		uint32(KMESH_TAIL_CALL_FILTER_CHAIN),
		uint32(sc.FilterChainManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return nil, err
	}

	err = sc.KmeshTailCallProg.Update(
		uint32(KMESH_TAIL_CALL_FILTER),
		uint32(sc.FilterManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *BpfSockOps) loadRouteConfigObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.Info.MapPath
	opts.Programs.LogSize = sc.Info.BpfVerifyLogSize

	err = sc.KmeshTailCallProg.Update(
		uint32(KMESH_TAIL_CALL_ROUTER_CONFIG),
		uint32(sc.RouteConfigManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *BpfSockOps) loadKmeshClusterObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.Info.MapPath
	opts.Programs.LogSize = sc.Info.BpfVerifyLogSize

	err = sc.KmeshTailCallProg.Update(
		uint32(KMESH_TAIL_CALL_CLUSTER),
		uint32(sc.ClusterManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *BpfSockOps) LoadSockOps() error {
	/* load kmesh sockops main bpf prog */
	spec, err := sc.loadKmeshSockopsObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["sockops_prog"]
	sc.Info.Type = prog.Type
	sc.Info.AttachType = prog.AttachType

	/* load kmesh sockops tail call bpf prog */
	if _, err := sc.loadKmeshFilterObjects(); err != nil {
		return err
	}

	if _, err := sc.loadRouteConfigObjects(); err != nil {
		return err
	}

	if _, err := sc.loadKmeshClusterObjects(); err != nil {
		return err
	}

	return nil
}

func (sc *BpfKmesh) Load() error {
	var err error

	if err = sc.TracePoint.LoadTracePoint(); err != nil {
		return err
	}

	if err = sc.SockOps.LoadSockOps(); err != nil {
		return err
	}

	if err = sc.SockConn.LoadSockConn(); err != nil {
		return err
	}

	return nil
}

func (sc *BpfKmesh) ApiEnvCfg() error {
	var err error
	var info *ebpf.MapInfo
	var id ebpf.MapID
	info, err = sc.SockOps.KmeshSockopsMaps.KmeshListener.Info()

	if err != nil {
		return err
	}

	id, _ = info.ID()
	stringId := strconv.Itoa(int(id))
	if err = os.Setenv("Listener", stringId); err != nil {
		return err
	}

	info, _ = sc.SockOps.KmeshSockopsMaps.OuterMap.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	if err = os.Setenv("OUTTER_MAP_ID", stringId); err != nil {
		return err
	}

	info, _ = sc.SockOps.KmeshSockopsMaps.InnerMap.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	if err = os.Setenv("INNER_MAP_ID", stringId); err != nil {
		return err
	}

	info, _ = sc.SockOps.MapOfRouterConfig.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	if err = os.Setenv("RouteConfiguration", stringId); err != nil {
		return err
	}

	info, _ = sc.SockOps.KmeshCluster.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	if err = os.Setenv("Cluster", stringId); err != nil {
		return err
	}

	return nil
}

func (sc *BpfTracePoint) Attach() error {
	tpopt := link.RawTracepointOptions{
		Name:    "connect_ret",
		Program: sc.KmeshTracePointObjects.ConnectRet,
	}

	lk, err := link.AttachRawTracepoint(tpopt)
	if err != nil {
		return err
	}
	sc.Link = lk

	return nil
}

func (sc *BpfSockOps) Attach() error {
	cgopt := link.CgroupOptions{
		Path:    sc.Info.Cgroup2Path,
		Attach:  sc.Info.AttachType,
		Program: sc.KmeshSockopsObjects.SockopsProg,
	}

	lk, err := link.AttachCgroup(cgopt)
	if err != nil {
		return err
	}
	sc.Link = lk

	return nil
}

func (sc *BpfKmesh) Attach() error {
	var err error

	if err = sc.TracePoint.Attach(); err != nil {
		return err
	}

	if err = sc.SockOps.Attach(); err != nil {
		return err
	}

	if err = sc.SockConn.Attach(); err != nil {
		return err
	}
	return nil
}

func (sc *BpfTracePoint) close() error {
	return sc.KmeshTracePointObjects.Close()
}

func (sc *BpfSockOps) close() error {
	if err := sc.KmeshSockopsObjects.Close(); err != nil {
		return err
	}
	return nil
}

func (sc *BpfKmesh) close() error {
	var err error

	if err = sc.SockOps.close(); err != nil {
		return err
	}

	if err = sc.SockConn.close(); err != nil {
		return err
	}

	if err = sc.TracePoint.close(); err != nil {
		return err
	}
	return nil
}

func (sc *BpfTracePoint) Detach() error {
	if err := sc.close(); err != nil {
		return err
	}

	if sc.Link != nil {
		return sc.Link.Close()
	}
	return nil
}

func (sc *BpfSockOps) Detach() error {
	var value reflect.Value

	if err := sc.close(); err != nil {
		return err
	}

	value = reflect.ValueOf(sc.KmeshSockopsObjects.KmeshSockopsPrograms)
	if err := unpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(sc.KmeshSockopsObjects.KmeshSockopsMaps)
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

func (sc *BpfKmesh) Detach() error {
	var err error

	if err = sc.TracePoint.Detach(); err != nil {
		return err
	}

	if err = sc.SockOps.Detach(); err != nil {
		return err
	}

	if err = sc.SockConn.Detach(); err != nil {
		return err
	}
	return nil
}
