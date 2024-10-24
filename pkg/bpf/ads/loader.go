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

package ads

// #cgo pkg-config: api-v2-c
// #include "deserialization_to_bpf_map.h"
import "C"
import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/cilium/ebpf"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/restart"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("bpf_ads")

type BpfAds struct {
	SockConn BpfSockConn
}

func NewBpfAds(cfg *options.BpfConfig) (*BpfAds, error) {
	sc := &BpfAds{}
	if err := sc.SockConn.NewBpf(cfg); err != nil {
		return nil, err
	}
	return sc, nil
}

func (sc *BpfAds) Start() error {
	var ve *ebpf.VerifierError

	if err := sc.Load(); err != nil {
		if errors.As(err, &ve) {
			return fmt.Errorf("bpf load failed: %+v", ve)
		}
		return fmt.Errorf("bpf load failed: %v", err)
	}

	if err := sc.Attach(); err != nil {
		return fmt.Errorf("bpf attach failed, %s", err)
	}

	if err := sc.ApiEnvCfg(); err != nil {
		return fmt.Errorf("api env config failed, %s", err)
	}

	ret := C.deserial_init(restart.GetStartType() == restart.Restart)
	if ret != 0 {
		return fmt.Errorf("deserial_init failed:%v", ret)
	}
	return nil
}

func (sc *BpfAds) GetBpfLogLevelMap() *ebpf.Map {
	return sc.SockConn.BpfLogLevel
}

func (sc *BpfAds) Stop() error {
	C.deserial_uninit(false)
	return sc.Detach()
}

func (sc *BpfAds) Load() error {
	if err := sc.SockConn.Load(); err != nil {
		return err
	}

	return nil
}

func (sc *BpfAds) ApiEnvCfg() error {
	info, err := sc.SockConn.KmeshCgroupSockMaps.KmeshListener.Info()
	if err != nil {
		return err
	}

	id, _ := info.ID()
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

func (sc *BpfAds) Attach() error {
	if err := sc.SockConn.Attach(); err != nil {
		return err
	}

	return nil
}

func (sc *BpfAds) Detach() error {
	if err := sc.SockConn.Detach(); err != nil {
		return err
	}
	return nil
}

func (sc *BpfAds) GetClusterStatsMap() *ebpf.Map {
	return sc.SockConn.KmeshCgroupSockMaps.MapOfClusterStats
}

func AdsL7Enabled() bool {
	return false
}
