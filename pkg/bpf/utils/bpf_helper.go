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

package utils

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func SetInnerMap(spec *ebpf.CollectionSpec) {
	var (
		InnerMapKeySize    uint32 = 4
		InnerMapDataLength uint32 = 1300 // C.BPF_INNER_MAP_DATA_LEN
		InnerMapMaxEntries uint32 = 1
	)
	for _, v := range spec.Maps {
		if v.Name == "outer_map" {
			v.InnerMap = &ebpf.MapSpec{
				Type:       ebpf.Array,
				KeySize:    InnerMapKeySize,
				ValueSize:  InnerMapDataLength,
				MaxEntries: InnerMapMaxEntries,
			}
		}
	}
}

func BpfProgUpdate(pinPath string, cgopt link.CgroupOptions) (link.Link, error) {
	sclink, err := link.LoadPinnedLink(pinPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return nil, err
	}
	if err := sclink.Update(cgopt.Program); err != nil {
		return nil, fmt.Errorf("updating link %s failed: %w", pinPath, err)
	}
	return sclink, nil
}

func BpfMapDeleteByPinPath(bpfFsPath string) error {
	progMap, err := ebpf.LoadPinnedMap(bpfFsPath, nil)
	if err != nil {
		return fmt.Errorf("loadPinnedProgram failed for %s: %v", bpfFsPath, err)
	}
	defer progMap.Close()
	if err := progMap.Unpin(); err != nil {
		return fmt.Errorf("unpin failed for %s: %v", bpfFsPath, err)
	}

	return nil
}
