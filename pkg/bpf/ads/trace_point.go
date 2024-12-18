//go:build enhanced
// +build enhanced

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
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	bpf2go "kmesh.net/kmesh/bpf/kmesh/bpf2go/kernelnative/enhanced"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/general"
	"kmesh.net/kmesh/pkg/bpf/restart"
	"kmesh.net/kmesh/pkg/constants"
	helper "kmesh.net/kmesh/pkg/utils"
)

type BpfTracePoint struct {
	Info general.BpfInfo
	Link link.Link
	bpf2go.KmeshTracePointObjects
}

func (sc *BpfTracePoint) NewBpf(cfg *options.BpfConfig) error {
	sc.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh/map/"
	sc.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh/tracepoint/"
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

func (sc *BpfTracePoint) loadKmeshTracePointObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	if helper.KernelVersionLowerThan5_13() {
		spec, err = bpf2go.LoadKmeshTracePointCompat()
	} else {
		spec, err = bpf2go.LoadKmeshTracePoint()
	}
	if err != nil || spec == nil {
		return nil, err
	}

	for _, v := range spec.Programs {
		if v.Name == "connect_ret" {
			v.Type = ebpf.RawTracepointWritable
		}
	}

	if err = spec.LoadAndAssign(&sc.KmeshTracePointObjects, &opts); err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *BpfTracePoint) Load() error {
	if _, err := sc.loadKmeshTracePointObjects(); err != nil {
		return err
	}
	return nil
}

func (sc *BpfTracePoint) Attach() error {
	var err error
	tpopt := link.RawTracepointOptions{
		Name:    "connect_ret",
		Program: sc.KmeshTracePointObjects.ConnectRet,
	}

	pinPath := filepath.Join(sc.Info.BpfFsPath, constants.Prog_link)
	if restart.GetStartType() == restart.Restart {
		sc.Link, err = link.LoadPinnedLink(pinPath, &ebpf.LoadPinOptions{})
		if err != nil {
			return err
		}
	} else {
		sc.Link, err = link.AttachRawTracepoint(tpopt)
		if err != nil {
			return err
		}

		if err := sc.Link.Pin(pinPath); err != nil {
			return err
		}

	}
	return nil
}

func (sc *BpfTracePoint) Detach() error {
	if err := sc.KmeshTracePointObjects.Close(); err != nil {
		return err
	}

	if sc.Link != nil {
		return sc.Link.Close()
	}
	return nil
}
