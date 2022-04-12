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
 * Create: 2022-02-15
 */

package bpf

// #cgo pkg-config: bpf api-v1-c
// #cgo LDFLAGS: -Wl,--allow-multiple-definition
import "C"
import (
	"fmt"
	"os"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"openeuler.io/mesh/bpf/slb/bpf2go"
)

type TcXdpRevnat struct {
	Info BpfInfo
	Link link.Link
	bpf2go.TcXdpRevnatObjects
}

func NewTcXdpRevnat(cfg *Config) (TcXdpRevnat, error) {
	tcRevNat := TcXdpRevnat{}
	tcRevNat.Info.Config = *cfg

	tcRevNat.Info.BpfFsPath += "/xdp_banlance/"
	tcRevNat.Info.MapPath = tcRevNat.Info.BpfFsPath + "map/"
	if err := os.MkdirAll(tcRevNat.Info.MapPath, 0750); err != nil && !os.IsExist(err) {
		return tcRevNat, err
	}

	return tcRevNat, nil
}

func (tc *TcXdpRevnat) LoadTcRevnatObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = tc.Info.MapPath

	if spec, err = bpf2go.LoadTcXdpRevnat(); err != nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&tc.TcXdpRevnatObjects, &opts); err != nil {
		return nil, fmt.Errorf("TcXdpRevnat: LoadAndAssign return err %s", err)
	}

	value := reflect.ValueOf(tc.TcXdpRevnatObjects.TcXdpRevnatPrograms)
	if err = pinPrograms(&value, tc.Info.BpfFsPath); err != nil {
		return nil, err
	}

	return spec, nil
}

func (tc *TcXdpRevnat) Load() error {
	if _, err := tc.LoadTcRevnatObjects(); err != nil {
		return err
	}

	return nil
}

func (tc *TcXdpRevnat) Attach() error {
	return nil
}

func (tc *TcXdpRevnat) close() error {
	if err := tc.TcXdpRevnatObjects.Close(); err != nil {
		return err
	}
	return nil
}

func (tc *TcXdpRevnat) Detach() error {
	var value reflect.Value

	if err := tc.close(); err != nil {
		return err
	}

	value = reflect.ValueOf(tc.TcXdpRevnatObjects.TcXdpRevnatPrograms)
	if err := unpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(tc.TcXdpRevnatObjects.TcXdpRevnatMaps)
	if err := unpinMaps(&value); err != nil {
		return err
	}

	if err := os.RemoveAll(tc.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if tc.Link != nil {
		return tc.Link.Close()
	}
	return nil
}
