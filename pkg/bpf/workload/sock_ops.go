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
	"kmesh.net/kmesh/pkg/bpf/general"
	"kmesh.net/kmesh/pkg/bpf/restart"
	"kmesh.net/kmesh/pkg/bpf/utils"
	helper "kmesh.net/kmesh/pkg/utils"
)

type BpfSockOpsWorkload struct {
	Info  general.BpfInfo
	Links []link.Link // store links for all three programs
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

	progs := map[string]*ebpf.Program{
		"sockops_active":  so.KmeshSockopsWorkloadObjects.SockopsActiveProg,
		"sockops_passive": so.KmeshSockopsWorkloadObjects.SockopsPassiveProg,
		"sockops_utils":   so.KmeshSockopsWorkloadObjects.SockopsUtilsProg,
	}

	for name, prog := range progs {
		if prog == nil {
			return fmt.Errorf("program %s not found in KmeshSockopsWorkloadObjects", name)
		}
	}

	// Using the first program to set Type and AttachType (they’re the same for all sock_ops)
	prog := spec.Programs["sockops_active_prog"]
	so.Info.Type = prog.Type
	so.Info.AttachType = prog.AttachType

	return nil
}

func (so *BpfSockOpsWorkload) Attach() error {
	progs := []struct {
		name string
		prog *ebpf.Program
	}{
		{"sockops_active", so.KmeshSockopsWorkloadObjects.SockopsActiveProg},
		{"sockops_passive", so.KmeshSockopsWorkloadObjects.SockopsPassiveProg},
		{"sockops_utils", so.KmeshSockopsWorkloadObjects.SockopsUtilsProg},
	}

	so.Links = make([]link.Link, 0, len(progs))

	for _, p := range progs {
		cgopt := link.CgroupOptions{
			Path:    so.Info.Cgroup2Path,
			Attach:  so.Info.AttachType,
			Program: p.prog,
		}
		pinPath := filepath.Join(so.Info.BpfFsPath, fmt.Sprintf("cgroup_%s_prog", p.name))

		var lk link.Link
		var err error
		if restart.GetStartType() == restart.Restart {
			lk, err = utils.BpfProgUpdate(pinPath, cgopt)
			if err != nil {
				return fmt.Errorf("failed to update %s: %v", p.name, err)
			}
		} else {
			lk, err = link.AttachCgroup(cgopt)
			if err != nil {
				return fmt.Errorf("failed to attach %s: %v", p.name, err)
			}
			if err := lk.Pin(pinPath); err != nil {
				return fmt.Errorf("failed to pin %s: %v", p.name, err)
			}
		}
		so.Links = append(so.Links, lk)
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

	programValue := reflect.ValueOf(so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadPrograms)
	if err := utils.UnpinPrograms(&programValue); err != nil {
		return err
	}

	mapValue := reflect.ValueOf(so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadMaps)
	if err := utils.UnpinMaps(&mapValue); err != nil {
		return err
	}

	if err := os.RemoveAll(so.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	for i, lnk := range so.Links {
		if lnk != nil {
			if err := lnk.Close(); err != nil {
				return fmt.Errorf("failed to close link %d: %v", i, err)
			}
		}
	}
	so.Links = nil

	return nil
}

func (so *BpfSockOpsWorkload) GetSockMapFD() int {
	return so.KmeshSockopsWorkloadObjects.KmeshSockopsWorkloadMaps.KmSocket.FD()
}
