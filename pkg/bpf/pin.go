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
 */

package bpf

import (
	"fmt"
	"reflect"

	"github.com/cilium/ebpf"
)

func pinPrograms(value *reflect.Value, path string) error {
	for i := 0; i < value.NumField(); i++ {
		tp, ok := value.Field(i).Interface().(*ebpf.Program)
		if tp == nil || !ok {
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
		tp, ok := value.Field(i).Interface().(*ebpf.Program)
		if !ok || tp == nil {
			continue
		}
		if err := tp.Unpin(); err != nil {
			return fmt.Errorf("unpin prog failed, %s", err)
		}
	}

	return nil
}

// Due to the golint issuse, comment unused functions temporaryly

// func pinMaps(value *reflect.Value, path string) error {
// 	for i := 0; i < value.NumField(); i++ {
// 		tp, ok := value.Field(i).Interface().(*ebpf.Map)
// 		if tp == nil || !ok {
// 			return fmt.Errorf("invalid pinMaps ptr")
// 		}

// 		info, err := tp.Info()
// 		if err != nil {
// 			return fmt.Errorf("get map info failed, %s", err)
// 		}
// 		if err := tp.Pin(path + info.Name); err != nil {
// 			return fmt.Errorf("pin map failed, %s", err)
// 		}
// 	}

// 	return nil
// }

func unpinMaps(value *reflect.Value) error {
	for i := 0; i < value.NumField(); i++ {
		tp, ok := value.Field(i).Interface().(*ebpf.Map)
		if tp == nil || !ok {
			continue
		}
		if err := tp.Unpin(); err != nil {
			return fmt.Errorf("unpin prog failed, %s", err)
		}
	}

	return nil
}

func setMapPinType(spec *ebpf.CollectionSpec, pinType ebpf.PinType) {
	for key, v := range spec.Maps {
		// tail_call map dont support pinning when shared by different bpf types
		if key == ".rodata" || key == ".bss" || key == "kmesh_tail_call_prog" ||
			key == "kmesh_tail_call_ctx" {
			continue
		}
		v.Pinning = pinType
	}
}

// Due to the golint issuse, comment unused functions temporaryly

// func setProgBpfType(spec *ebpf.CollectionSpec, typ ebpf.ProgramType, atyp ebpf.AttachType) {
// 	for _, v := range spec.Programs {
// 		v.Type = typ
// 		v.AttachType = atyp
// 	}
// }
