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
	"os"
	"syscall"

	"github.com/cilium/ebpf/link"

	bpf2go "kmesh.net/kmesh/bpf/kmesh/bpf2go/dualengine"
	"kmesh.net/kmesh/daemon/options"

	"kmesh.net/kmesh/pkg/bpf/general"
)

type BpfTcWorkload struct {
	Info general.BpfInfo
	Link link.Link
	bpf2go.KmeshTcWorkloadObjects
}

func (so *BpfSockOpsWorkload) NewBpf(cfg *options.BpfConfig) error {
	so.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	so.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/tc/"
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
