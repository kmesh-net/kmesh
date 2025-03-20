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
	"syscall"

	"github.com/cilium/ebpf"

	bpf2go "kmesh.net/kmesh/bpf/kmesh/bpf2go/dualengine"
	"kmesh.net/kmesh/daemon/options"

	"kmesh.net/kmesh/pkg/bpf/general"
	"kmesh.net/kmesh/pkg/bpf/utils"
	helper "kmesh.net/kmesh/pkg/utils"
)

type BpfTcWorkload struct {
	Info general.BpfInfo
	bpf2go.KmeshTcWorkloadObjects
}

func (tc *BpfTcWorkload) NewBpf(cfg *options.BpfConfig) error {
	tc.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	tc.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/tcp_tc/"
	tc.Info.Cgroup2Path = cfg.Cgroup2Path

	if err := os.MkdirAll(tc.Info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(tc.Info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (tc *BpfTcWorkload) loadKmeshTcObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)

	opts.Maps.PinPath = tc.Info.MapPath
	if helper.KernelVersionLowerThan5_13() {
		spec, err = bpf2go.LoadKmeshTcWorkloadCompat()
	} else {
		spec, err = bpf2go.LoadKmeshTcWorkload()
	}
	if err != nil {
		return nil, err
	}
	if spec == nil {
		return nil, fmt.Errorf("error: loadKmeshTcObjects() spec is nil")
	}

	utils.SetMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&tc.KmeshTcWorkloadObjects, &opts); err != nil {
		return nil, err
	}

	return spec, nil
}

func (tc *BpfTcWorkload) LoadTc() error {
	/* load kmesh  main bpf prog*/
	spec, err := tc.loadKmeshTcObjects()
	if err != nil {
		return err
	}
	prog := spec.Programs["tc_prog"]
	tc.Info.Type = prog.Type
	tc.Info.AttachType = prog.AttachType

	return nil
}
