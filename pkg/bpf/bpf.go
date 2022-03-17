/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2021-10-09
 */

package bpf

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"openeuler.io/mesh/pkg/logger"
)


type BpfInfo struct {
	Config
	MapPath		string
	Type		ebpf.ProgramType
	AttachType	ebpf.AttachType
}

type BpfObject struct {
	Kmesh BpfKmesh
	Slb BpfSlb
	XdpBalance  BpfXdpBalance
}

var Obj BpfObject

func StartKmesh() error {
	var err error

	if Obj.Kmesh, err = NewBpfKmesh(&config); err != nil {
		return err
	}

	if err = Obj.Kmesh.Load(); err != nil {
		Stop()
		return fmt.Errorf("bpf Load failed, %s", err)
	}

	if err = Obj.Kmesh.Attach(); err != nil {
		Stop()
		return fmt.Errorf("bpf Attach failed, %s", err)
	}

	if err = Obj.Kmesh.ApiEnvCfg(); err != nil {
                Stop()
                return fmt.Errorf("api env config failed, %s", err)
        }

	return nil
}

func StartSlb() error {
	var err error

	if Obj.Slb, err = NewBpfSlb(&config); err != nil {
		return err
	}

	if err = Obj.Slb.Load(); err != nil {
		Stop()
		return fmt.Errorf("bpf Load failed, %s", err)
	}

	if err = Obj.Slb.Attach(); err != nil {
		Stop()
		return fmt.Errorf("bpf Attach failed, %s", err)
	}
	return nil
}

func Start() error {
	var err error

	if err = rlimit.RemoveMemlock(); err != nil {
		return err
	}

	if config.EnableKmesh {
		if err = StartKmesh(); err != nil {
			return err
		}
	}

	if config.EnableSlb {
		if err = StartSlb(); err != nil {
			return err
		}
		if err = StartXdpBalance(); err != nil {
			Stop()
			return fmt.Errorf("bpf StartXdpBalance failed, %s", err)
		}
	}

	return nil
}

func Stop() error {
	var err error

	if config.EnableKmesh {
		if err = Obj.Kmesh.Detach(); err != nil {
			return err
		}
	}

	if config.EnableSlb {
		if err := Obj.XdpBalance.Detach(); err != nil {
			return fmt.Errorf("failed to detach XdpBalance, err:%s", err)
		}
		if err = Obj.Slb.Detach(); err != nil {
			return err
		}
	}

	return nil
}

func StartXdpBalance() error {
	var err error
	if Obj.XdpBalance, err = NewXdpBalance(&config); err != nil {
		return err
	}

	if err = Obj.XdpBalance.Load(); err != nil {
		return fmt.Errorf("bpf xdp_banlance Load failed, %s", err)
	}

	if err = Obj.XdpBalance.Attach(); err != nil {
		return fmt.Errorf("bpf xdp_banlance Attach failed, %s", err)
	}
	return nil
}
