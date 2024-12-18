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

package general

import (
	"fmt"
	"os"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
	"kmesh.net/kmesh/bpf/kmesh/bpf2go/general"
	bpf2go_general "kmesh.net/kmesh/bpf/kmesh/bpf2go/general"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/utils"
	"kmesh.net/kmesh/pkg/constants"
	helper "kmesh.net/kmesh/pkg/utils"
)

type BpfTCGeneral struct {
	InfoTcMarkDecrypt BpfInfo
	InfoTcMarkEncrypt BpfInfo
	bpf2go_general.KmeshTcMarkDecryptObjects
	bpf2go_general.KmeshTcMarkEncryptObjects
}

func (tc *BpfTCGeneral) newBpf(info *BpfInfo, cfg *options.BpfConfig) error {
	info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/tc/"
	info.Cgroup2Path = cfg.Cgroup2Path

	if err := os.MkdirAll(info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (tc *BpfTCGeneral) NewBpf(cfg *options.BpfConfig) error {
	if err := tc.newBpf(&tc.InfoTcMarkDecrypt, cfg); err != nil {
		return err
	}
	if err := tc.newBpf(&tc.InfoTcMarkEncrypt, cfg); err != nil {
		return err
	}

	return nil
}

func (tc *BpfTCGeneral) loadKmeshTCObjects() (*ebpf.CollectionSpec, *ebpf.CollectionSpec, error) {
	var (
		errTcMarkDecrypt  error
		errTcMarkEncrypt  error
		specTcMarkDecrypt *ebpf.CollectionSpec
		optsTcMarkDecrypt ebpf.CollectionOptions
		specTcMarkEncrypt *ebpf.CollectionSpec
		optsTcMarkEncrypt ebpf.CollectionOptions
	)

	optsTcMarkDecrypt.Maps.PinPath = tc.InfoTcMarkDecrypt.MapPath
	optsTcMarkEncrypt.Maps.PinPath = tc.InfoTcMarkEncrypt.MapPath
	if helper.KernelVersionLowerThan5_13() {
		specTcMarkDecrypt, errTcMarkDecrypt = general.LoadKmeshTcMarkDecryptCompat()
		specTcMarkEncrypt, errTcMarkEncrypt = general.LoadKmeshTcMarkEncryptCompat()
	} else {
		specTcMarkDecrypt, errTcMarkDecrypt = general.LoadKmeshTcMarkDecrypt()
		specTcMarkEncrypt, errTcMarkEncrypt = general.LoadKmeshTcMarkEncrypt()
	}
	if errTcMarkDecrypt != nil {
		return nil, nil, errTcMarkDecrypt
	}
	if errTcMarkEncrypt != nil {
		return nil, nil, errTcMarkEncrypt
	}
	if specTcMarkDecrypt == nil || specTcMarkEncrypt == nil {
		return nil, nil, fmt.Errorf("error: loadKmeshTCObjects() spec is nil")
	}

	utils.SetMapPinType(specTcMarkDecrypt, ebpf.PinByName)
	if err := specTcMarkDecrypt.LoadAndAssign(&tc.KmeshTcMarkDecryptObjects, &optsTcMarkDecrypt); err != nil {
		return nil, nil, err
	}

	utils.SetMapPinType(specTcMarkEncrypt, ebpf.PinByName)
	if err := specTcMarkEncrypt.LoadAndAssign(&tc.KmeshTcMarkEncryptObjects, &optsTcMarkEncrypt); err != nil {
		return nil, nil, err
	}

	return specTcMarkDecrypt, specTcMarkEncrypt, nil
}

func (tc *BpfTCGeneral) LoadTC() error {
	specMarkDecrypt, specMarkEncrypt, err := tc.loadKmeshTCObjects()
	if err != nil {
		return err
	}

	prog := specMarkDecrypt.Programs[constants.TC_MARK_DECRYPT]
	tc.InfoTcMarkDecrypt.Type = prog.Type
	tc.InfoTcMarkDecrypt.AttachType = prog.AttachType

	prog = specMarkEncrypt.Programs[constants.TC_MARK_ENCRYPT]
	tc.InfoTcMarkEncrypt.Type = prog.Type
	tc.InfoTcMarkEncrypt.AttachType = prog.AttachType

	return nil
}

func (tc *BpfTCGeneral) Close() error {
	if err := tc.KmeshTcMarkDecryptObjects.Close(); err != nil {
		return err
	}
	progVal := reflect.ValueOf(tc.KmeshTcMarkDecryptObjects.KmeshTcMarkDecryptPrograms)
	if err := utils.UnpinPrograms(&progVal); err != nil {
		return err
	}

	mapVal := reflect.ValueOf(tc.KmeshTcMarkDecryptObjects.KmeshTcMarkDecryptMaps)
	if err := utils.UnpinMaps(&mapVal); err != nil {
		return err
	}

	if err := os.RemoveAll(tc.InfoTcMarkDecrypt.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if err := tc.KmeshTcMarkEncryptObjects.Close(); err != nil {
		return err
	}
	progVal = reflect.ValueOf(tc.KmeshTcMarkEncryptObjects.KmeshTcMarkEncryptPrograms)
	if err := utils.UnpinPrograms(&progVal); err != nil {
		return err
	}

	mapVal = reflect.ValueOf(tc.KmeshTcMarkEncryptObjects.KmeshTcMarkEncryptMaps)
	if err := utils.UnpinMaps(&mapVal); err != nil {
		return err
	}

	if err := os.RemoveAll(tc.InfoTcMarkEncrypt.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
