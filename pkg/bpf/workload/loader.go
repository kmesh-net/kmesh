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

package workload

// #cgo pkg-config: api-v2-c
// #include "deserialization_to_bpf_map.h"
import "C"
import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/factory"
	"kmesh.net/kmesh/pkg/bpf/general"
	"kmesh.net/kmesh/pkg/bpf/utils"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("bpf_workload")

type BpfWorkload struct {
	SockConn  SockConnWorkload
	SockOps   BpfSockOpsWorkload
	XdpAuth   BpfXdpAuthWorkload
	SendMsg   BpfSendMsgWorkload
	CgroupSkb BpfCroupSkbWorkload
	Tc        *general.BpfTCGeneral
}

func NewBpfWorkload(cfg *options.BpfConfig) (*BpfWorkload, error) {
	workloadObj := &BpfWorkload{}

	if err := workloadObj.SockConn.NewBpf(cfg); err != nil {
		return nil, err
	}

	if err := workloadObj.SockOps.NewBpf(cfg); err != nil {
		return nil, err
	}

	if err := workloadObj.CgroupSkb.NewBpf(cfg); err != nil {
		return nil, err
	}
	if err := workloadObj.XdpAuth.NewBpf(cfg); err != nil {
		return nil, err
	}

	// we must pass pointer here, because workloadObj.SockOps will be modified during loading
	if err := workloadObj.SendMsg.NewBpf(cfg, &workloadObj.SockOps); err != nil {
		return nil, err
	}

	if cfg.EnableIPsec {
		var err error
		workloadObj.Tc, err = general.NewBpf(cfg)
		if err != nil {
			return nil, err
		}
	}
	return workloadObj, nil
}

func (w *BpfWorkload) Start() error {
	var ve *ebpf.VerifierError

	if err := w.Load(); err != nil {
		if errors.As(err, &ve) {
			return fmt.Errorf("bpf Load failed: %+v", ve)
		}
		return fmt.Errorf("bpf Load failed: %v", err)
	}

	if err := w.Attach(); err != nil {
		return fmt.Errorf("bpf Attach failed, %s", err)
	}

	if err := w.ApiEnvCfg(); err != nil {
		return fmt.Errorf("failed to set api env")
	}

	ret := C.deserial_init()
	if ret != 0 {
		return fmt.Errorf("deserial_init failed:%v", ret)
	}
	return nil
}

func (w *BpfWorkload) Stop() error {
	C.deserial_uninit()
	return w.Detach()
}

func (w *BpfWorkload) GetBpfConfigVariable() factory.KmeshBpfConfig {
	return factory.KmeshBpfConfig{
		BpfLogLevel:      w.SockOps.BpfLogLevel,
		NodeIP:           w.SockOps.NodeIp,
		PodGateway:       w.SockOps.PodGateway,
		AuthzOffload:     w.XdpAuth.AuthzOffload,
		EnableMonitoring: w.SockOps.EnableMonitoring,
	}
}

func (w *BpfWorkload) Load() error {
	if err := w.SockConn.LoadSockConn(); err != nil {
		return err
	}

	if err := w.SockOps.LoadSockOps(); err != nil {
		return err
	}

	if err := w.XdpAuth.LoadXdpAuth(); err != nil {
		return err
	}

	if err := w.SendMsg.LoadSendMsg(); err != nil {
		return err
	}

	if err := w.CgroupSkb.LoadCgroupSkb(); err != nil {
		return err
	}

	if err := w.Tc.LoadTC(); err != nil {
		return err
	}
	return nil
}

func (w *BpfWorkload) Attach() error {
	if err := w.SockConn.Attach(); err != nil {
		return err
	}

	if err := w.SockOps.Attach(); err != nil {
		return err
	}

	if err := w.SendMsg.Attach(); err != nil {
		return err
	}

	if err := w.CgroupSkb.Attach(); err != nil {
		return err
	}

	return nil
}

func (w *BpfWorkload) Detach() error {
	if err := w.SockConn.Detach(); err != nil {
		return err
	}

	if err := w.SendMsg.Detach(); err != nil {
		return err
	}

	if err := w.CgroupSkb.Detach(); err != nil {
		return err
	}

	if err := w.SockOps.Detach(); err != nil {
		return err
	}

	if err := w.XdpAuth.Close(); err != nil {
		return err
	}

	if err := w.Tc.Close(); err != nil {
		return err
	}

	return nil
}

func (w *BpfWorkload) ApiEnvCfg() error {
	var err error

	if err = utils.SetEnvByBpfMapId(w.XdpAuth.KmeshXDPAuthMaps.KmAuthzPolicy, "Authorization"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(w.XdpAuth.KmeshMap64, "KmeshMap64"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(w.XdpAuth.KmeshMap192, "KmeshMap192"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(w.XdpAuth.KmeshMap296, "KmeshMap296"); err != nil {
		return err
	}

	if err = utils.SetEnvByBpfMapId(w.XdpAuth.KmeshMap1600, "KmeshMap1600"); err != nil {
		return err
	}
	return nil
}
