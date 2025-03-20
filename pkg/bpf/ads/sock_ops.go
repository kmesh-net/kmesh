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

import (
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/restart"
	"kmesh.net/kmesh/pkg/bpf/utils"
	"kmesh.net/kmesh/pkg/constants"
)

func (sc *BpfSockOps) NewBpf(cfg *options.BpfConfig) error {
	sc.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh/map/"
	sc.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh/sockops/"
	sc.Info.Cgroup2Path = cfg.Cgroup2Path

	if err := os.MkdirAll(sc.Info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(sc.Info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (sc *BpfSockOps) loadKmeshSockopsObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)

	opts.Maps.PinPath = sc.Info.MapPath
	spec, err = loadKmeshSockOps()
	if err != nil || spec == nil {
		return nil, err
	}

	utils.SetMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sc.KmeshSockopsObjects, &opts); err != nil {
		return nil, err
	}

	return spec, nil
}
func (sc *BpfSockOps) Load() error {
	/* load kmesh sockops main bpf prog */
	spec, err := sc.loadKmeshSockopsObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["sockops_prog"]
	sc.Info.Type = prog.Type
	sc.Info.AttachType = prog.AttachType

	return nil
}

func (sc *BpfSockOps) Attach() error {
	var err error
	cgopt := link.CgroupOptions{
		Path:    sc.Info.Cgroup2Path,
		Attach:  sc.Info.AttachType,
		Program: sc.KmeshSockopsObjects.SockopsProg,
	}

	// pin bpf_link
	progPinPath := filepath.Join(sc.Info.BpfFsPath, constants.Prog_link)
	if restart.GetStartType() == restart.Restart {
		if sc.Link, err = utils.BpfProgUpdate(progPinPath, cgopt); err != nil {
			return err
		}
	} else {
		sc.Link, err = link.AttachCgroup(cgopt)
		if err != nil {
			return err
		}
		if err = sc.Link.Pin(progPinPath); err != nil {
			return err
		}
	}
	return nil
}

func (sc *BpfSockOps) Detach() error {
	var value reflect.Value

	if err := sc.KmeshSockopsObjects.Close(); err != nil {
		return err
	}

	value = reflect.ValueOf(sc.KmeshSockopsObjects.KmeshSockopsPrograms)
	if err := utils.UnpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(sc.KmeshSockopsObjects.KmeshSockopsMaps)
	if err := utils.UnpinMaps(&value); err != nil {
		return err
	}

	if err := os.RemoveAll(sc.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if sc.Link != nil {
		return sc.Link.Close()
	}
	return nil
}
