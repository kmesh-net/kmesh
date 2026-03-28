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
	"strings"

	"github.com/cilium/ebpf"
)

func GetProgramByName(name string) (*ebpf.Program, error) {
	var (
		progID         ebpf.ProgramID
		err            error
		targetProg     *ebpf.Program
		targetProgInfo *ebpf.ProgramInfo
	)

	progID = ebpf.ProgramID(0)

	for {
		if progID, err = ebpf.ProgramGetNextID(progID); err != nil {
			return nil, fmt.Errorf("failed to get system next program id: %w", err)
		}

		if targetProg, err = ebpf.NewProgramFromID(progID); err != nil {
			return nil, fmt.Errorf("failed to get new program from id:%v: %w", progID, err)
		}

		if targetProgInfo, err = targetProg.Info(); err != nil {
			targetProg.Close()
			return nil, fmt.Errorf("failed to get program info for id:%v: %w", progID, err)
		}

		if strings.Compare(targetProgInfo.Name, name) == 0 {
			return targetProg, nil
		}

		targetProg.Close()
	}
}

func GetMapByName(name string) (*ebpf.Map, error) {
	var (
		mapID         ebpf.MapID
		err           error
		targetMap     *ebpf.Map
		targetMapInfo *ebpf.MapInfo
	)

	mapID = ebpf.MapID(0)

	for {
		if mapID, err = ebpf.MapGetNextID(mapID); err != nil {
			return nil, fmt.Errorf("failed to get system next map id: %w", err)
		}

		if targetMap, err = ebpf.NewMapFromID(mapID); err != nil {
			return nil, fmt.Errorf("failed to get new map from id:%v: %w", mapID, err)
		}

		if targetMapInfo, err = targetMap.Info(); err != nil {
			targetMap.Close()
			return nil, fmt.Errorf("failed to get map info for id:%v: %w", mapID, err)
		}

		if strings.Compare(targetMapInfo.Name, name) == 0 {
			return targetMap, nil
		}

		targetMap.Close()
	}
}
