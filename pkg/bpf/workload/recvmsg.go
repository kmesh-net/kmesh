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

type BpfRecvMsgWorkload struct {
	Info     general.BpfInfo
	AttachFD int
	bpf2go.KmeshRecvmsgObjects

	sockOpsWorkloadObj *BpfSockOpsWorkload
}

func (sm *BpfRecvMsgWorkload) NewBpf(cfg *options.BpfConfig, sockOpsWorkloadObj *BpfSockOpsWorkload) error {
	sm.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	sm.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/recvmsg/"
	sm.Info.Cgroup2Path = cfg.Cgroup2Path
	sm.sockOpsWorkloadObj = sockOpsWorkloadObj

	if err := os.MkdirAll(sm.Info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(sm.Info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (sm *BpfRecvMsgWorkload) loadKmeshRecvmsgObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)

	opts.Maps.PinPath = sm.Info.MapPath
	if helper.KernelVersionLowerThan5_13() {
		spec, err = bpf2go.LoadKmeshRecvmsgCompat()
	} else {
		spec, err = bpf2go.LoadKmeshRecvmsg()
	}
	if err != nil || spec == nil {
		return nil, err
	}

	utils.SetMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sm.KmeshRecvmsgObjects, &opts); err != nil {
		return nil, err
	}

	// bpflink for sk_skb is supported in kernel 6.13, so we update recvmsg manually here
	// sendmsg ebpf prog is mounted on sockmap and processed for each socket.
	// It has the following characteristics:
	// 1. Multiple sk_skb ebpf prog can exist at the same time
	// 2. If the old sk_skb ebpf program is not pinned, it will wait until all
	// sockets on the old sk_skb ebpf prog are disconnected before automatically detaching.
	// Therefore, the following methods are used to achieve seamless replacement
	// 1) loading new sk_skb prog
	// 2) unpin old sk_skb prog: If sockmap is deleted, sk_skb will also be cleaned up
	// 3) pin new sk_skb prog
	// 4) attach new sk_skb prog(in RecvMsg.Attach): Replace the old sk_skb prog
	if restart.GetStartType() == restart.Restart {
		pinPath := filepath.Join(sm.Info.BpfFsPath, "recvmsg_prog")
		oldSkSkb, err := ebpf.LoadPinnedProgram(pinPath, nil)
		if err != nil {
			log.Errorf("LoadPinnedProgram failed: %v", err)
			return nil, err
		}

		if err = oldSkSkb.Unpin(); err != nil {
			return nil, err
		}
	}

	value := reflect.ValueOf(sm.KmeshRecvmsgObjects.KmeshRecvmsgPrograms)
	if err = utils.PinPrograms(&value, sm.Info.BpfFsPath); err != nil {
		return nil, err
	}
	return spec, nil
}

func (sm *BpfRecvMsgWorkload) LoadRecvMsg() error {
	/* load kmesh recvmsg main bpf prog */
	spec, err := sm.loadKmeshRecvmsgObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["recvmsg_prog"]
	sm.Info.Type = prog.Type
	sm.Info.AttachType = prog.AttachType
	return nil
}

func (sm *BpfRecvMsgWorkload) Attach() error {
	// Use a program handle that cannot be closed by the caller
	clone, err := sm.KmeshRecvmsgObjects.KmeshRecvmsgPrograms.RecvmsgProg.Clone()
	if err != nil {
		return err
	}

	sm.AttachFD = sm.sockOpsWorkloadObj.GetSockMapFD()
	args := link.RawAttachProgramOptions{
		Target:  sm.AttachFD,
		Program: clone,
		Flags:   0,
		Attach:  ebpf.AttachSkSKBVerdict,
	}

	if err = link.RawAttachProgram(args); err != nil {
		return err
	}
	return nil
}

func (sm *BpfRecvMsgWorkload) Detach() error {
	if sm.AttachFD > 0 {
		args := link.RawDetachProgramOptions{
			Target:  sm.AttachFD,
			Program: sm.KmeshRecvmsgObjects.KmeshRecvmsgPrograms.RecvmsgProg,
			Attach:  ebpf.AttachSkSKBVerdict,
		}

		if err := link.RawDetachProgram(args); err != nil {
			return err
		}
	}

	program_value := reflect.ValueOf(sm.KmeshRecvmsgObjects.KmeshRecvmsgPrograms)
	if err := utils.UnpinPrograms(&program_value); err != nil {
		return err
	}

	if err := os.RemoveAll(sm.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if err := sm.KmeshRecvmsgObjects.Close(); err != nil {
		return err
	}
	return nil
}
