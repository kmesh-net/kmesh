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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	bpf2go "kmesh.net/kmesh/bpf/kmesh/bpf2go/kernelnative/normal"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/factory"
	"kmesh.net/kmesh/pkg/bpf/general"
	"kmesh.net/kmesh/pkg/bpf/utils"
	"kmesh.net/kmesh/pkg/consistenthash/maglev"
	"kmesh.net/kmesh/pkg/logger"
	helper "kmesh.net/kmesh/pkg/utils"
)

var log = logger.NewLoggerScope("bpf_ads")

type BpfAds struct {
	SockConn BpfSockConn
	SockOps  BpfSockOps
	Tc       *general.BpfTCGeneral
}

type BpfSockConn struct {
	Info general.BpfInfo
	Link link.Link
	bpf2go.KmeshCgroupSockObjects
}

type BpfSockOps struct {
	Info general.BpfInfo
	Link link.Link
	bpf2go.KmeshSockopsObjects
}

func loadKmeshCgroupSock() (*ebpf.CollectionSpec, error) {
	var spec *ebpf.CollectionSpec
	var err error
	if helper.KernelVersionLowerThan5_13() {
		spec, err = bpf2go.LoadKmeshCgroupSockCompat()
	} else {
		spec, err = bpf2go.LoadKmeshCgroupSock()
	}
	return spec, err
}

func loadKmeshSockOps() (*ebpf.CollectionSpec, error) {
	var spec *ebpf.CollectionSpec
	var err error
	if helper.KernelVersionLowerThan5_13() {
		spec, err = bpf2go.LoadKmeshSockops()
	} else {
		spec, err = bpf2go.LoadKmeshSockopsCompat()
	}
	return spec, err
}

func NewBpfAds(cfg *options.BpfConfig) (*BpfAds, error) {
	sc := &BpfAds{}

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

	ret := C.deserial_init()
	if ret != 0 {
		return fmt.Errorf("deserial_init failed:%v", ret)
	}

	if err := maglev.InitMaglevMap(); err != nil {
		return fmt.Errorf("consistent hash lb maglev config init failed, %s", err)
	}

	return nil
}

func (sc *BpfAds) GetBpfConfigVariable() factory.KmeshBpfConfig {
	return factory.KmeshBpfConfig{
		BpfLogLevel: sc.SockConn.BpfLogLevel,
	}
}

func (sc *BpfAds) Stop() error {
	C.deserial_uninit()
	return sc.Detach()
}

func (sc *BpfAds) Load() error {
	if err := sc.SockConn.Load(); err != nil {
		return err
	}

	if err := sc.SockOps.Load(); err != nil {
		return err
	}

	if err := sc.Tc.LoadTC(); err != nil {
		return err
	}

	return nil
}

func (sc *BpfAds) ApiEnvCfg() error {
	var err error

	if err = utils.SetEnvByBpfMapId(sc.SockConn.KmeshCgroupSockMaps.KmListener, "Listener"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(sc.SockConn.KmCluster, "Cluster"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(sc.SockConn.KmeshMap64, "KmeshMap64"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(sc.SockConn.KmeshMap192, "KmeshMap192"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(sc.SockConn.KmeshMap296, "KmeshMap296"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(sc.SockConn.KmeshMap1600, "KmeshMap1600"); err != nil {
		return err
	}
	return nil
}

func (sc *BpfAds) Attach() error {
	if err := sc.SockOps.Attach(); err != nil {
		return err
	}

	if err := sc.SockConn.Attach(); err != nil {
		return err
	}

	return nil
}

func (sc *BpfAds) Detach() error {
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
	return sc.SockConn.KmeshCgroupSockMaps.KmClusterstats
}

func AdsL7Enabled() bool {
	return false
}
