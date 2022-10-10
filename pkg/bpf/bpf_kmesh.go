/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *	 http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: nlgwcy
 * Create: 2022-02-26
 */

package bpf

// #cgo pkg-config: bpf api-v2-c
// #include "kmesh/include/tail_call.h"
import "C"
import (
	"os"
	"reflect"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"openeuler.io/mesh/bpf/kmesh/bpf2go"
)

var (
	InnerMapKeySize    uint32 = 4
	InnerMapDataLength uint32 = 1300
	InnerMapMaxEntries uint32 = 1
)

type BpfSockConn struct {
	Info BpfInfo
	Link link.Link
	bpf2go.KmeshCgroupSockObjects
}

type BpfSockOps struct {
	Info BpfInfo
	Link link.Link
	bpf2go.KmeshSockopsObjects
	bpf2go.KmeshFilterObjects
	bpf2go.KmeshRouteConfigObjects
	bpf2go.KmeshClusterObjects
}

type BpfKmesh struct {
	SockConn BpfSockConn
	SockOps  BpfSockOps
}

func (sc *BpfSockOps) NewBpf(cfg *Config) error {
	sc.Info.Config = *cfg
	sc.Info.BpfFsPath += "/bpf_kmesh/"
	sc.Info.MapPath = sc.Info.BpfFsPath + "map/"

	if err := os.MkdirAll(sc.Info.MapPath, 0750); err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

func (sc *BpfSockConn) NewBpf(cfg *Config) error {
	sc.Info.Config = *cfg
	sc.Info.BpfFsPath += "/bpf_kmesh/"
	sc.Info.MapPath = sc.Info.BpfFsPath + "map/"

	if err := os.MkdirAll(sc.Info.MapPath, 0750); err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

func NewBpfKmesh(cfg *Config) (BpfKmesh, error) {
	var err error

	sc := BpfKmesh{}
	if err = sc.SockOps.NewBpf(cfg); err != nil {
		return sc, err
	}

	if err = sc.SockConn.NewBpf(cfg); err != nil {
		return sc, err
	}
	return sc, nil
}

func setInnerMap(spec *ebpf.CollectionSpec) {
	// TODO
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

func (sc *BpfSockOps) loadKmeshSockopsObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.Info.MapPath

	if spec, err = bpf2go.LoadKmeshSockops(); err != nil {
		return nil, err
	}

	setInnerMap(spec)
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

	if spec, err = bpf2go.LoadKmeshFilter(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	setProgBpfType(spec, sc.Info.Type, sc.Info.AttachType)
	if err = spec.LoadAndAssign(&sc.KmeshFilterObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sc.KmeshFilterObjects.KmeshFilterPrograms)
	if err = pinPrograms(&value, sc.Info.BpfFsPath); err != nil {
		return nil, err
	}

	err = sc.KmeshFilterObjects.KmeshFilterMaps.KmeshTailCallProg.Update(
		uint32(C.KMESH_TAIL_CALL_FILTER_CHAIN),
		uint32(sc.KmeshFilterObjects.KmeshFilterPrograms.FilterChainManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return nil, err
	}

	err = sc.KmeshFilterObjects.KmeshFilterMaps.KmeshTailCallProg.Update(
		uint32(C.KMESH_TAIL_CALL_FILTER),
		uint32(sc.KmeshFilterObjects.KmeshFilterPrograms.FilterManager.FD()),
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

	if spec, err = bpf2go.LoadKmeshRouteConfig(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	setProgBpfType(spec, sc.Info.Type, sc.Info.AttachType)
	if err = spec.LoadAndAssign(&sc.KmeshRouteConfigObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sc.KmeshRouteConfigObjects.KmeshRouteConfigPrograms)
	if err = pinPrograms(&value, sc.Info.BpfFsPath); err != nil {
		return nil, err
	}

	err = sc.KmeshRouteConfigObjects.KmeshRouteConfigMaps.KmeshTailCallProg.Update(
		uint32(C.KMESH_TAIL_CALL_ROUTER_CONFIG),
		uint32(sc.KmeshRouteConfigObjects.KmeshRouteConfigPrograms.RouteConfigManager.FD()),
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

	if spec, err = bpf2go.LoadKmeshCluster(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	setProgBpfType(spec, sc.Info.Type, sc.Info.AttachType)
	if err = spec.LoadAndAssign(&sc.KmeshClusterObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sc.KmeshClusterObjects.KmeshClusterPrograms)
	if err = pinPrograms(&value, sc.Info.BpfFsPath); err != nil {
		return nil, err
	}

	err = sc.KmeshClusterObjects.KmeshClusterMaps.KmeshTailCallProg.Update(
		uint32(C.KMESH_TAIL_CALL_CLUSTER),
		uint32(sc.KmeshClusterObjects.KmeshClusterPrograms.ClusterManager.FD()),
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

func (sc *BpfSockConn) loadKmeshSockConnObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.Info.MapPath

	if spec, err = bpf2go.LoadKmeshCgroupSock(); err != nil {
		return nil, err
	}

	setInnerMap(spec)
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

	return nil
}

func (sc *BpfKmesh) Load() error {
	var err error

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
	info, err = Obj.Kmesh.SockOps.KmeshSockopsMaps.KmeshListener.Info()

	if err != nil {
		return err
	}

	id, _ = info.ID()
	stringId := strconv.Itoa(int(id))
	os.Setenv("Listener", stringId)

	info, _ = Obj.Kmesh.SockOps.KmeshSockopsMaps.OuterMap.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	os.Setenv("OUTTER_MAP_ID", stringId)

	info, _ = Obj.Kmesh.SockOps.KmeshSockopsMaps.InnerMap.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	os.Setenv("INNER_MAP_ID", stringId)

	info, _ = Obj.Kmesh.SockOps.MapOfRouterConfig.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	os.Setenv("RouteConfiguration", stringId)

	info, _ = Obj.Kmesh.SockOps.KmeshCluster.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	os.Setenv("Cluster", stringId)

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

func (sc *BpfKmesh) Attach() error {
	var err error

	if err = sc.SockOps.Attach(); err != nil {
		return err
	}

	if err = sc.SockConn.Attach(); err != nil {
		return err
	}
	return nil
}

func (sc *BpfSockOps) close() error {
	if err := sc.KmeshSockopsObjects.Close(); err != nil {
		return err
	}
	if err := sc.KmeshFilterObjects.Close(); err != nil {
		return err
	}
	if err := sc.KmeshRouteConfigObjects.Close(); err != nil {
		return err
	}
	if err := sc.KmeshClusterObjects.Close(); err != nil {
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

func (sc *BpfKmesh) close() error {
	var err error

	if err = sc.SockOps.close(); err != nil {
		return err
	}

	if err = sc.SockConn.close(); err != nil {
		return err
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

func (sc *BpfKmesh) Detach() error {
	var err error

	if err = sc.SockOps.Detach(); err != nil {
		return err
	}

	if err = sc.SockConn.Detach(); err != nil {
		return err
	}
	return nil
}
