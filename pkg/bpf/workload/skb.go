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

type BpfCroupSkbWorkload struct {
	Info   general.BpfInfo
	Link   link.Link
	InfoEg general.BpfInfo
	LinkEg link.Link
	bpf2go.KmeshCgroupSkbObjects
}

func (cs *BpfCroupSkbWorkload) NewBpf(cfg *options.BpfConfig) error {
	cs.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	cs.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/cgroup_skb/"
	cs.Info.Cgroup2Path = cfg.Cgroup2Path
	cs.InfoEg = cs.Info
	if err := os.MkdirAll(cs.Info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(cs.Info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (cs *BpfCroupSkbWorkload) loadKmeshCgroupSkbObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)

	opts.Maps.PinPath = cs.Info.MapPath

	if helper.KernelVersionLowerThan5_13() {
		spec, err = bpf2go.LoadKmeshCgroupSkbCompat()
	} else {
		spec, err = bpf2go.LoadKmeshCgroupSkb()
	}
	if err != nil {
		return nil, err
	}
	if spec == nil {
		return nil, fmt.Errorf("error: loadKmeshCgroupSkbObjects() spec is nil")
	}

	utils.SetMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&cs.KmeshCgroupSkbObjects, &opts); err != nil {
		return nil, err
	}

	return spec, nil
}

func (cs *BpfCroupSkbWorkload) LoadCgroupSkb() error {
	/* load kmesh recvmsg main bpf prog*/
	spec, err := cs.loadKmeshCgroupSkbObjects()
	if err != nil {
		return err
	}

	progIn := spec.Programs["cgroup_skb_ingress_prog"]
	cs.Info.Type = progIn.Type
	cs.Info.AttachType = progIn.AttachType
	progEg := spec.Programs["cgroup_skb_egress_prog"]
	cs.InfoEg.Type = progEg.Type
	cs.InfoEg.AttachType = progEg.AttachType

	return nil
}

func (cs *BpfCroupSkbWorkload) Attach() error {
	var err error
	cgopt := link.CgroupOptions{
		Path:    cs.Info.Cgroup2Path,
		Attach:  cs.Info.AttachType,
		Program: cs.KmeshCgroupSkbObjects.CgroupSkbIngressProg,
	}
	cgopt2 := link.CgroupOptions{
		Path:    cs.InfoEg.Cgroup2Path,
		Attach:  cs.InfoEg.AttachType,
		Program: cs.KmeshCgroupSkbObjects.CgroupSkbEgressProg,
	}
	pinPathIn := filepath.Join(cs.Info.BpfFsPath, "cgroup_skb_ingress_prog")
	pinPathEg := filepath.Join(cs.Info.BpfFsPath, "cgroup_skb_egress_prog")
	if restart.GetStartType() == restart.Restart {
		if cs.Link, err = utils.BpfProgUpdate(pinPathIn, cgopt); err != nil {
			return err
		}
		if cs.LinkEg, err = utils.BpfProgUpdate(pinPathIn, cgopt2); err != nil {
			return err
		}
	} else {
		lk, err := link.AttachCgroup(cgopt)
		if err != nil {
			return err
		}
		cs.Link = lk

		if err := lk.Pin(pinPathIn); err != nil {
			return err
		}
		lk2, err := link.AttachCgroup(cgopt2)
		if err != nil {
			return err
		}
		cs.LinkEg = lk2
		if err := lk2.Pin(pinPathEg); err != nil {
			return err
		}
	}

	return nil
}

func (cs *BpfCroupSkbWorkload) close() error {
	if err := cs.KmeshCgroupSkbObjects.Close(); err != nil {
		return err
	}
	return nil
}

func (cs *BpfCroupSkbWorkload) Detach() error {
	if err := cs.close(); err != nil {
		return err
	}

	program_value := reflect.ValueOf(cs.KmeshCgroupSkbObjects.KmeshCgroupSkbPrograms)
	if err := utils.UnpinPrograms(&program_value); err != nil {
		return err
	}

	map_value := reflect.ValueOf(cs.KmeshCgroupSkbObjects.KmeshCgroupSkbMaps)
	if err := utils.UnpinMaps(&map_value); err != nil {
		return err
	}

	if err := os.RemoveAll(cs.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if cs.Link != nil {
		return cs.Link.Close()
	}

	if cs.LinkEg != nil {
		return cs.LinkEg.Close()
	}
	return nil
}
