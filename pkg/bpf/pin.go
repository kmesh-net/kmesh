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

import (
	"fmt"
	"github.com/cilium/ebpf"
	"reflect"
)

func pinPrograms(value *reflect.Value, path string) error {
	for i := 0; i < value.NumField(); i++ {
		tp := value.Field(i).Interface().(*ebpf.Program)
		if tp == nil {
			return fmt.Errorf("invalid pinPrograms ptr")
		}

		info, err := tp.Info()
		if err != nil {
			return fmt.Errorf("get prog info failed, %s", err)
		}
		if err := tp.Pin(path + info.Name); err != nil {
			return fmt.Errorf("pin prog failed, %s", err)
		}
	}

	return nil
}

func unpinPrograms(value *reflect.Value) error {
	for i := 0; i < value.NumField(); i++ {
		tp := value.Field(i).Interface().(*ebpf.Program)
		if tp == nil {
			continue
		}
		if err := tp.Unpin(); err != nil {
			return fmt.Errorf("unpin prog failed, %s", err)
		}
	}

	return nil
}

func pinMaps(value *reflect.Value, path string) error {
	for i := 0; i < value.NumField(); i++ {
		tp := value.Field(i).Interface().(*ebpf.Map)
		if tp == nil {
			return fmt.Errorf("invalid pinMaps ptr")
		}

		info, err := tp.Info()
		if err != nil {
			return fmt.Errorf("get map info failed, %s", err)
		}
		if err := tp.Pin(path + info.Name); err != nil {
			return fmt.Errorf("pin map failed, %s", err)
		}
	}

	return nil
}

func unpinMaps(value *reflect.Value) error {
	for i := 0; i < value.NumField(); i++ {
		tp := value.Field(i).Interface().(*ebpf.Map)
		if tp == nil {
			continue
		}
		if err := tp.Unpin(); err != nil {
			return fmt.Errorf("unpin prog failed, %s", err)
		}
	}

	return nil
}

func setMapPinType(spec *ebpf.CollectionSpec, pinType ebpf.PinType) {
	for _, v := range spec.Maps {
		v.Pinning = pinType
	}
}

func setProgBpfType(spec *ebpf.CollectionSpec, typ ebpf.ProgramType, atyp ebpf.AttachType) {
	for _, v := range spec.Programs {
		v.Type = typ
		v.AttachType = atyp
	}
}