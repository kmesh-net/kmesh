//go:build enhanced
// +build enhanced

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
	TracePoint BpfTracePoint
	SockConn   BpfSockConn
	SockOps    BpfSockOps
}

func NewBpfAds(cfg *options.BpfConfig) (*BpfAds, error) {
	sc := &BpfAds{}
	if err := sc.TracePoint.NewBpf(cfg); err != nil {
		return nil, err
	}

	if err := sc.SockOps.NewBpf(cfg); err != nil {
		return nil, err
	}

	if err := sc.SockConn.NewBpf(cfg); err != nil {
		return nil, err
	}
	return sc, nil
}

func (sc *BpfAds) Start() error {
	var ve *ebpf.VerifierError

	if err := sc.Load(); err != nil {
		if errors.As(err, &ve) {
			return fmt.Errorf("bpf Load failed: %+v", ve)
		}
		return fmt.Errorf("bpf Load failed: %v", err)
	}

	if err := sc.Attach(); err != nil {
		return fmt.Errorf("bpf Attach failed, %s", err)
	}

	if err := sc.ApiEnvCfg(); err != nil {
		return fmt.Errorf("failed to set api env")
	}

	ret := C.deserial_init(restart.GetStartType() == restart.Restart)
	if ret != 0 {
		return fmt.Errorf("deserial_init failed:%v", ret)
	}
	return nil
}

func (sc *BpfAds) Stop() error {
	C.deserial_uninit(false)
	if err := sc.Detach(); err != nil {
		log.Errorf("failed detach when stop kmesh, err: %v", err)
		return err
	}
	return nil
}

func (sc *BpfAds) GetBpfLogLevelMap() *ebpf.Map {
	return sc.SockConn.BpfLogLevel
}

func (sc *BpfAds) Load() error {
	if err := sc.TracePoint.Load(); err != nil {
		return err
	}

	if err := sc.SockOps.Load(); err != nil {
		return err
	}

	if err := sc.SockConn.Load(); err != nil {
		return err
	}

	return nil
}

func (sc *BpfAds) ApiEnvCfg() error {
	var id ebpf.MapID
	info, err := sc.SockOps.KmeshSockopsMaps.KmeshListener.Info()
	if err != nil {
		return err
	}

	id, _ = info.ID()
	stringId := strconv.Itoa(int(id))
	if err := os.Setenv("Listener", stringId); err != nil {
		return err
	}

	info, _ = sc.SockOps.KmeshSockopsMaps.OuterMap.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	if err := os.Setenv("OUTTER_MAP_ID", stringId); err != nil {
		return err
	}

	info, _ = sc.SockOps.KmeshSockopsMaps.InnerMap.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	if err := os.Setenv("INNER_MAP_ID", stringId); err != nil {
		return err
	}

	info, _ = sc.SockOps.MapOfRouterConfig.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	if err := os.Setenv("RouteConfiguration", stringId); err != nil {
		return err
	}

	info, _ = sc.SockOps.KmeshCluster.Info()
	id, _ = info.ID()
	stringId = strconv.Itoa(int(id))
	if err := os.Setenv("Cluster", stringId); err != nil {
		return err
	}

	return nil
}

func (sc *BpfAds) Attach() error {
	if err := sc.TracePoint.Attach(); err != nil {
		return err
	}

	if err := sc.SockOps.Attach(); err != nil {
		return err
	}

	if err := sc.SockConn.Attach(); err != nil {
		return err
	}
	return nil
}

func (sc *BpfAds) Detach() error {
	if err := sc.TracePoint.Detach(); err != nil {
		return err
	}

	if err := sc.SockOps.Detach(); err != nil {
		return err
	}

	if err := sc.SockConn.Detach(); err != nil {
		return err
	}
	return nil
}

func AdsL7Enabled() bool {
	return false
}
