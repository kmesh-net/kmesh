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

	"kmesh.net/kmesh/bpf/kmesh/bpf2go"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/restart"
	"kmesh.net/kmesh/pkg/bpf/utils"
)

func bpfProgUpdate(pinPath string, cgopt link.CgroupOptions) error {
	sclink, err := link.LoadPinnedLink(pinPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return err
	}
	if err := sclink.Update(cgopt.Program); err != nil {
		return fmt.Errorf("updating link %s failed: %w", pinPath, err)
	}
	return nil
}

type BpfSendMsgWorkload struct {
	Info     BpfInfo
	AttachFD int
	bpf2go.KmeshSendmsgObjects

	sockOpsWorkloadObj *BpfSockOpsWorkload
}

func (sm *BpfSendMsgWorkload) NewBpf(cfg *options.BpfConfig, sockOpsWorkloadObj *BpfSockOpsWorkload) error {
	sm.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	sm.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/sendmsg/"
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

func (sm *BpfSendMsgWorkload) loadKmeshSendmsgObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)

	opts.Maps.PinPath = sm.Info.MapPath
	if spec, err = bpf2go.LoadKmeshSendmsg(); err != nil {
		return nil, err
	}

	utils.SetMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sm.KmeshSendmsgObjects, &opts); err != nil {
		return nil, err
	}

	// bpflink for sk_msg is supported in kernel 6.13, so we update sendmsg manually here
	// sendmsg ebpf prog is mounted on sockmap and processed for each socket.
	// It has the following characteristics:
	// 1. Multiple sk_msg ebpf prog can exist at the same time
	// 2. If the old sk_msg ebpf program is not pinned, it will wait until all
	// sockets on the old sk_msg ebpf prog are disconnected before automatically detaching.
	// Therefore, the following methods are used to achieve seamless replacement
	// 1) loading new sk_msg prog
	// 2) unpin old sk_msg prog: If sockmap is deleted, sk_msg will also be cleaned up
	// 3) pin new sk_msg prog
	// 4) attach new sk_msg prog(in SendMsg.Attach): Replace the old sk_msg prog
	if restart.GetStartType() == restart.Restart {
		pinPath := filepath.Join(sm.Info.BpfFsPath, "sendmsg_prog")
		oldSkMsg, err := ebpf.LoadPinnedProgram(pinPath, nil)
		if err != nil {
			log.Errorf("LoadPinnedProgram failed: %v", err)
			return nil, err
		}

		if err = oldSkMsg.Unpin(); err != nil {
			return nil, err
		}
	}

	value := reflect.ValueOf(sm.KmeshSendmsgObjects.KmeshSendmsgPrograms)
	if err = utils.PinPrograms(&value, sm.Info.BpfFsPath); err != nil {
		return nil, err
	}
	return spec, nil
}

func (sm *BpfSendMsgWorkload) LoadSendMsg() error {
	/* load kmesh sendmsg main bpf prog */
	spec, err := sm.loadKmeshSendmsgObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["sendmsg_prog"]
	sm.Info.Type = prog.Type
	sm.Info.AttachType = prog.AttachType
	return nil
}

func (sm *BpfSendMsgWorkload) Attach() error {
	// Use a program handle that cannot be closed by the caller
	clone, err := sm.KmeshSendmsgObjects.KmeshSendmsgPrograms.SendmsgProg.Clone()
	if err != nil {
		return err
	}

	sm.AttachFD = sm.sockOpsWorkloadObj.GetSockMapFD()
	args := link.RawAttachProgramOptions{
		Target:  sm.AttachFD,
		Program: clone,
		Flags:   0,
		Attach:  ebpf.AttachSkMsgVerdict,
	}

	if err = link.RawAttachProgram(args); err != nil {
		return err
	}
	return nil
}

func (sm *BpfSendMsgWorkload) Detach() error {
	if sm.AttachFD > 0 {
		args := link.RawDetachProgramOptions{
			Target:  sm.AttachFD,
			Program: sm.KmeshSendmsgObjects.KmeshSendmsgPrograms.SendmsgProg,
			Attach:  ebpf.AttachSkMsgVerdict,
		}

		if err := link.RawDetachProgram(args); err != nil {
			return err
		}
	}

	program_value := reflect.ValueOf(sm.KmeshSendmsgObjects.KmeshSendmsgPrograms)
	if err := utils.UnpinPrograms(&program_value); err != nil {
		return err
	}

	if err := os.RemoveAll(sm.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if err := sm.KmeshSendmsgObjects.Close(); err != nil {
		return err
	}
	return nil
}
