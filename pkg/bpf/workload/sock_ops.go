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
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	bpf2go "kmesh.net/kmesh/bpf/kmesh/bpf2go/dualengine"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/restart"
	"kmesh.net/kmesh/pkg/bpf/utils"
	helper "kmesh.net/kmesh/pkg/utils"
)

type BpfSockOpsWorkload struct {
	Info BpfInfo
	Link link.Link
	bpf2go.KmeshSockopsWorkloadObjects
}

func (so *BpfSockOpsWorkload) NewBpf(cfg *options.BpfConfig) error {
	so.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	so.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/sockops/"
	so.Info.Cgroup2Path = cfg.Cgroup2Path

	if err := os.MkdirAll(so.Info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(so.Info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (so *BpfSockOpsWorkload) loadKmeshSockopsObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)

	opts.Maps.PinPath = so.Info.MapPath

	if helper.KernelVersionLowerThan5_13() {
		spec, err = bpf2go.LoadKmeshSockopsWorkloadCompat()
	} else {
		spec, err = bpf2go.LoadKmeshSockopsWorkload()
	}
	if err != nil {
		return nil, err
	}
	if spec == nil {
		return nil, fmt.Errorf("error: loadKmeshSockopsObjects() spec is nil")
	}

	utils.SetMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&so.KmeshSockopsWorkloadObjects, &opts); err != nil {
		return nil, err
	}

	return spec, nil
}

func (so *BpfSockOpsWorkload) LoadSockOps() error {
	/* load kmesh sockops main bpf prog*/
	spec, err := so.loadKmeshSockopsObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["sockops_prog"]
	so.Info.Type = prog.Type
	so.Info.AttachType = prog.AttachType

	return nil
}

func (so *BpfSockOpsWorkload) Attach() error {
	cgopt := link.CgroupOptions{
		Path:    so.Info.Cgroup2Path,
		Attach:  so.Info.AttachType,
		Program: so.KmeshSockopsWorkloadObjects.SockopsProg,
	}
	pinPath := filepath.Join(so.Info.BpfFsPath, "cgroup_sockops_prog")

	if restart.GetStartType() == restart.Restart {
		if err := bpfProgUpdate(pinPath, cgopt); err != nil {
			return err
		}
	} else {
		lk, err := link.AttachCgroup(cgopt)
		if err != nil {
			return err
		}
		so.Link = lk

		if err := lk.Pin(pinPath); err != nil {
			return err
		}
	}

	return nil
}

func (so *BpfSockOpsWorkload) close() error {
	if err := so.KmeshSockopsWorkloadObjects.Close(); err != nil {
		return err
	}
	return nil
}

func (so *BpfSockOpsWorkload) Detach() error {
	if err := so.close(); err != nil {
		return err
	}

	program_value := reflect.ValueOf(so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadPrograms)
	if err := utils.UnpinPrograms(&program_value); err != nil {
		return err
	}

	map_value := reflect.ValueOf(so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadMaps)
	if err := utils.UnpinMaps(&map_value); err != nil {
		return err
	}

	if err := os.RemoveAll(so.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if so.Link != nil {
		return so.Link.Close()
	}
	return nil
}

func (so *BpfSockOpsWorkload) GetSockMapFD() int {
	return so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadMaps.MapOfKmeshSocket.FD()
}
