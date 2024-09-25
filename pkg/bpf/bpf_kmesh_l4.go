//go:build !enhanced
// +build !enhanced

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

package bpf

import (
	"os"
	"strconv"

	"github.com/cilium/ebpf"

	"kmesh.net/kmesh/daemon/options"
)

type BpfKmesh struct {
	SockConn BpfSockConn
}

func NewBpfKmesh(cfg *options.BpfConfig) (*BpfKmesh, error) {
	var err error

	sc := &BpfKmesh{}

	if err = sc.SockConn.NewBpf(cfg); err != nil {
		return nil, err
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

	info, err = sc.SockConn.KmeshCgroupSockMaps.KmeshListener.Info()

	if err != nil {
		return err
	}

	id, _ = info.ID()
	stringId := strconv.Itoa(int(id))
	if err = os.Setenv("Listener", stringId); err != nil {
		return err
	}

	info, _ = sc.SockConn.KmeshCgroupSockMaps.OuterMap.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	if err = os.Setenv("OUTTER_MAP_ID", stringId); err != nil {
		return err
	}

	info, _ = sc.SockConn.KmeshCgroupSockMaps.InnerMap.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	if err = os.Setenv("INNER_MAP_ID", stringId); err != nil {
		return err
	}

	info, _ = sc.SockConn.KmeshCluster.Info()
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

func (sc *BpfKmesh) Detach() error {
	var err error

	if err = sc.SockConn.Detach(); err != nil {
		return err
	}
	return nil
}

func AdsL7Enabled() bool {
	return false
}
