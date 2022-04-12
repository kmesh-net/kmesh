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
// #cgo LDFLAGS: -Wl,--allow-multiple-definition
// #include "slb/tail_call.h"
import "C"
import (
	"fmt"
	"os"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"openeuler.io/mesh/bpf/slb/bpf2go"
)

var (
	GlobalMapPath   = "/sys/fs/bpf/tc/globals/"
	XdpProgPath     = "/xdp_balance/"
	AttachInterface = 2
)

type BpfXdpBalance struct {
	Info BpfInfo
	Link link.Link
	bpf2go.XdpBalanceObjects
	bpf2go.XdpClusterObjects
}

func NewXdpBalance(cfg *Config) (BpfXdpBalance, error) {
	xdpBalance := BpfXdpBalance{}
	xdpBalance.Info.Config = *cfg

	xdpBalance.Info.BpfFsPath += XdpProgPath
	// xdpBalance.Info.MapPath = xdpBalance.Info.BpfFsPath + "map/"
	// shared map to tcRevNat bpf
	xdpBalance.Info.MapPath = GlobalMapPath
	if err := os.MkdirAll(xdpBalance.Info.BpfFsPath, 0750); err != nil && !os.IsExist(err) {
		return xdpBalance, err
	}
	if err := os.MkdirAll(xdpBalance.Info.MapPath, 0750); err != nil && !os.IsExist(err) {
		return xdpBalance, err
	}

	return xdpBalance, nil
}

func (xdpB *BpfXdpBalance) LoadXdpBalanceObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = xdpB.Info.MapPath

	if spec, err = bpf2go.LoadXdpBalance(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&xdpB.XdpBalanceObjects, &opts); err != nil {
		return nil, fmt.Errorf("LoadAndAssign return err %s", err)
	}

	value := reflect.ValueOf(xdpB.XdpBalanceObjects.XdpBalancePrograms)
	if err = pinPrograms(&value, xdpB.Info.BpfFsPath); err != nil {
		return nil, err
	}

	return spec, nil
}

func (xdpB *BpfXdpBalance) loadXdpClusterObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = xdpB.Info.MapPath

	if spec, err = bpf2go.LoadXdpCluster(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	setProgBpfType(spec, xdpB.Info.Type, xdpB.Info.AttachType)
	if err = spec.LoadAndAssign(&xdpB.XdpClusterObjects, &opts); err != nil {
		return nil, fmt.Errorf("LoadAndAssign return err %s", err)
	}

	value := reflect.ValueOf(xdpB.XdpClusterObjects.XdpClusterPrograms)
	if err = pinPrograms(&value, xdpB.Info.BpfFsPath); err != nil {
		return nil, err
	}

	err = xdpB.XdpClusterObjects.XdpClusterMaps.TailCallProg.Update(
		uint32(C.KMESH_TAIL_CALL_CLUSTER),
		uint32(xdpB.XdpClusterObjects.XdpClusterPrograms.ClusterManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return nil, err
	}

	return spec, nil
}

func (xdpB *BpfXdpBalance) Load() error {
	spec, err := xdpB.LoadXdpBalanceObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["xdp_load_balance"]
	xdpB.Info.Type = prog.Type
	xdpB.Info.AttachType = prog.AttachType

	if _, err := xdpB.loadXdpClusterObjects(); err != nil {
		return err
	}

	return nil
}

func (xdpB *BpfXdpBalance) Attach() error {
	xdpOpts := link.XDPOptions{
		Program: xdpB.XdpBalanceObjects.XdpLoadBalance,
		// todo xsy get by command:ip link show set in config
		Interface: AttachInterface,
		Flags:     link.XDPGenericMode,
	}

	lk, err := link.AttachXDP(xdpOpts)
	if err != nil {
		return err
	}
	xdpB.Link = lk

	return nil
}

func (xdpB *BpfXdpBalance) close() error {
	if err := xdpB.XdpBalanceObjects.Close(); err != nil {
		return err
	}

	if err := xdpB.XdpClusterObjects.Close(); err != nil {
		return err
	}

	return nil
}

func (xdpB *BpfXdpBalance) Detach() error {
	var value reflect.Value

	if err := xdpB.close(); err != nil {
		return err
	}

	value = reflect.ValueOf(xdpB.XdpBalanceObjects.XdpBalancePrograms)
	if err := unpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(xdpB.XdpBalanceObjects.XdpBalanceMaps)
	if err := unpinMaps(&value); err != nil {
		return err
	}

	if err := os.RemoveAll(xdpB.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if xdpB.Link != nil {
		return xdpB.Link.Close()
	}
	return nil
}
