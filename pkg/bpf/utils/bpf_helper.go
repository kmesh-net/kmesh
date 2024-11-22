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
	"os"
	"strconv"

	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func SetEnvByBpfMapId(m *ebpf.Map, key string) error {
	info, _ := m.Info()
	id, _ := info.ID()
	stringId := strconv.Itoa(int(id))
	return os.Setenv(key, stringId)
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

// func BpfMapDeleteByPinPath(bpfFsPath string) error {
// 	progMap, err := ebpf.LoadPinnedMap(bpfFsPath, nil)
// 	if err != nil {
// 		return fmt.Errorf("loadPinnedMap failed for %s: %v, when kmesh delete by pin path", bpfFsPath, err)
// 	}
// 	defer progMap.Close()
// 	if err := progMap.Unpin(); err != nil {
// 		return fmt.Errorf("unpin failed for %s: %v", bpfFsPath, err)
// 	}

// 	return nil
// }
