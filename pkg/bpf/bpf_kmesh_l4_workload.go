/*
 * Copyright 2024 The Kmesh Authors.
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
	"fmt"

	"kmesh.net/kmesh/daemon/options"
)

type BpfKmeshWorkload struct {
	SockConn BpfSockConnWorkload
	SockOps  BpfSockOpsWorkload
	XdpAuth  BpfXdpAuthWorkload
	SendMsg  BpfSendMsgWorkload
}

func newWorkloadBpf(cfg *options.BpfConfig) (*BpfKmeshWorkload, error) {
	workloadObj := &BpfKmeshWorkload{}

	if err := workloadObj.SockConn.NewBpf(cfg); err != nil {
		return nil, err
	}

	if err := workloadObj.SockOps.NewBpf(cfg); err != nil {
		return nil, err
	}

	if err := workloadObj.XdpAuth.NewBpf(cfg); err != nil {
		return nil, err
	}

	// we must pass pointer here, because workloadObj.SockOps will be modified during loading
	if err := workloadObj.SendMsg.NewBpf(cfg, &workloadObj.SockOps); err != nil {
		return nil, err
	}

	return workloadObj, nil
}

func (l *BpfLoader) StartWorkloadMode() error {
	var err error

	if l.workloadObj, err = newWorkloadBpf(l.config); err != nil {
		return err
	}

	if err = l.workloadObj.Load(); err != nil {
		l.Stop()
		return fmt.Errorf("bpf Load failed, %s", err)
	}

	if err = l.workloadObj.Attach(); err != nil {
		l.Stop()
		return fmt.Errorf("bpf Attach failed, %s", err)
	}
	l.bpfLogLevel = l.workloadObj.SockConn.BpfLogLevel
	return nil
}

func (sc *BpfKmeshWorkload) Load() error {
	var err error

	if err = sc.SockConn.LoadSockConn(); err != nil {
		return err
	}

	if err = sc.SockOps.LoadSockOps(); err != nil {
		return err
	}

	if err = sc.XdpAuth.LoadXdpAuth(); err != nil {
		return err
	}

	if err = sc.SendMsg.LoadSendMsg(); err != nil {
		return err
	}
	return nil
}

func (sc *BpfKmeshWorkload) Attach() error {
	var err error

	if err = sc.SockConn.Attach(); err != nil {
		return err
	}

	if err = sc.SockOps.Attach(); err != nil {
		return err
	}

	if err = sc.SendMsg.Attach(); err != nil {
		return err
	}

	return nil
}

func (sc *BpfKmeshWorkload) Detach() error {
	var err error

	if err = sc.SockConn.Detach(); err != nil {
		return err
	}

	if err = sc.SendMsg.Detach(); err != nil {
		return err
	}

	if err = sc.SockOps.Detach(); err != nil {
		return err
	}

	if err = sc.XdpAuth.Close(); err != nil {
		return err
	}

	return nil
}
