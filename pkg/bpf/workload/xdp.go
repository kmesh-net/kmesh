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

import (
	"fmt"
	"os"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"

	bpf2go "kmesh.net/kmesh/bpf/kmesh/bpf2go/dualengine"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/utils"
	"kmesh.net/kmesh/pkg/constants"
	helper "kmesh.net/kmesh/pkg/utils"
)

type BpfXdpAuthWorkload struct {
	Info BpfInfo
	bpf2go.KmeshXDPAuthObjects
}

func (xa *BpfXdpAuthWorkload) NewBpf(cfg *options.BpfConfig) error {
	xa.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	xa.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/xdpauth/"
	xa.Info.Cgroup2Path = cfg.Cgroup2Path

	if err := os.MkdirAll(xa.Info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(xa.Info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (xa *BpfXdpAuthWorkload) loadKmeshXdpAuthObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)

	opts.Maps.PinPath = xa.Info.MapPath
	if helper.KernelVersionLowerThan5_13() {
		spec, err = bpf2go.LoadKmeshXDPAuthCompat()
	} else {
		spec, err = bpf2go.LoadKmeshXDPAuth()
	}
	if err != nil {
		return nil, err
	}
	if spec == nil {
		return nil, fmt.Errorf("error: loadKmeshXdpAuthObjects() spec is nil")
	}

	utils.SetMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&xa.KmeshXDPAuthObjects, &opts); err != nil {
		return nil, err
	}

	return spec, nil
}

func (xa *BpfXdpAuthWorkload) LoadXdpAuth() error {
	spec, err := xa.loadKmeshXdpAuthObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs[constants.XDP_PROG_NAME]
	xa.Info.Type = prog.Type
	xa.Info.AttachType = prog.AttachType

	if err = xa.KmXdpTailcall.Update(
		uint32(constants.TailCallPoliciesCheck),
		uint32(xa.PoliciesCheck.FD()),
		ebpf.UpdateAny); err != nil {
		return err
	}

	if err = xa.KmXdpTailcall.Update(
		uint32(constants.TailCallPolicyCheck),
		uint32(xa.PolicyCheck.FD()),
		ebpf.UpdateAny); err != nil {
		return err
	}

	if err = xa.KmXdpTailcall.Update(
		uint32(constants.TailCallAuthInUserSpace),
		uint32(xa.XdpShutdownInUserspace.FD()),
		ebpf.UpdateAny); err != nil {
		return err
	}

	return nil
}

func (xa *BpfXdpAuthWorkload) Close() error {
	if err := xa.KmeshXDPAuthObjects.Close(); err != nil {
		return err
	}
	progVal := reflect.ValueOf(xa.KmeshXDPAuthObjects.KmeshXDPAuthPrograms)
	if err := utils.UnpinPrograms(&progVal); err != nil {
		return err
	}

	mapVal := reflect.ValueOf(xa.KmeshXDPAuthObjects.KmeshXDPAuthMaps)
	if err := utils.UnpinMaps(&mapVal); err != nil {
		return err
	}

	if err := os.RemoveAll(xa.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
