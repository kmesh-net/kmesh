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

	"github.com/cilium/ebpf"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/general"
	"kmesh.net/kmesh/pkg/bpf/utils"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("bpf_ads")

type BpfAds struct {
	TracePoint BpfTracePoint
	SockConn   BpfSockConn
	SockOps    BpfSockOps
	Tc         *general.BpfTCGeneral
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

	if cfg.EnableIPsec {
		var err error
		sc.Tc, err = general.NewBpf(cfg)
		if err != nil {
			return nil, err
		}
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

	ret := C.deserial_init()
	if ret != 0 {
		return fmt.Errorf("deserial_init failed:%v", ret)
	}
	return nil
}

func (sc *BpfAds) Stop() error {
	C.deserial_uninit()
	if err := sc.Detach(); err != nil {
		log.Errorf("failed detach when stop kmesh, err: %v", err)
		return err
	}
	return nil
}

func (sc *BpfAds) GetKmeshConfigMap() *ebpf.Map {
	return sc.SockConn.KmConfigmap
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

	if err := sc.Tc.LoadTC(); err != nil {
		return err
	}

	return nil
}

func (sc *BpfAds) ApiEnvCfg() error {
	var err error

	if err = utils.SetEnvByBpfMapId(sc.SockOps.KmeshSockopsMaps.KmListener, "Listener"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(sc.SockOps.KmRouterconfig, "RouteConfiguration"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(sc.SockOps.KmCluster, "Cluster"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(sc.SockOps.KmeshMap64, "KmeshMap64"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(sc.SockOps.KmeshMap192, "KmeshMap192"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(sc.SockOps.KmeshMap296, "KmeshMap296"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(sc.SockOps.KmeshMap1600, "KmeshMap1600"); err != nil {
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

	if err := sc.Tc.Close(); err != nil {
		return err
	}

	return nil
}

func (sc *BpfAds) GetClusterStatsMap() *ebpf.Map {
	return sc.SockOps.KmeshSockopsMaps.KmClusterstats
}

func AdsL7Enabled() bool {
	return false
}
