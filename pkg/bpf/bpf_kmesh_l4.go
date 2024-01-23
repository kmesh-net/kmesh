//go:build !enhanced
// +build !enhanced

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

 * Author: lec-bit
 * Create: 2023-11-02
 */

package bpf

import (
	"os"
	"strconv"

	"github.com/cilium/ebpf"
)

type BpfKmesh struct {
	SockConn BpfSockConn
}

func NewBpfKmesh(cfg *Config) (BpfKmesh, error) {
	var err error

	sc := BpfKmesh{}

	if err = sc.SockConn.NewBpf(cfg); err != nil {
		return sc, err
	}
	return sc, nil
}

func (sc *BpfKmesh) Load() error {
	var err error

	if err = sc.SockConn.LoadSockConn(); err != nil {
		return err
	}

	return nil
}

func (sc *BpfKmesh) ApiEnvCfg() error {
	var err error
	var info *ebpf.MapInfo
	var id ebpf.MapID

	info, err = Obj.Kmesh.SockConn.KmeshCgroupSockMaps.KmeshListener.Info()

	if err != nil {
		return err
	}

	id, _ = info.ID()
	stringId := strconv.Itoa(int(id))
	if err = os.Setenv("Listener", stringId); err != nil {
		return err
	}

	info, _ = Obj.Kmesh.SockConn.KmeshCgroupSockMaps.OuterMap.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	if err = os.Setenv("OUTTER_MAP_ID", stringId); err != nil {
		return err
	}

	info, _ = Obj.Kmesh.SockConn.KmeshCgroupSockMaps.InnerMap.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	if err = os.Setenv("INNER_MAP_ID", stringId); err != nil {
		return err
	}

	info, _ = Obj.Kmesh.SockConn.KmeshCluster.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	if err = os.Setenv("Cluster", stringId); err != nil {
		return err
	}
	return nil
}

func (sc *BpfKmesh) Attach() error {
	var err error

	if err = sc.SockConn.Attach(); err != nil {
		return err
	}

	return nil
}

// Due to the golint issuse, comment unused functions temporaryly

// func (sc *BpfKmesh) close() error {
// 	var err error

// 	if err = sc.SockConn.close(); err != nil {
// 		return err
// 	}

// 	return nil
// }

func (sc *BpfKmesh) Detach() error {
	var err error

	if err = sc.SockConn.Detach(); err != nil {
		return err
	}
	return nil
}
