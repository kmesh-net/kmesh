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
	InfoTcMarkEncrypt BpfInfo
	InfoTcMarkDecrypt BpfInfo
	bpf2go_general.KmeshTcMarkEncryptObjects
	bpf2go_general.KmeshTcMarkDecryptObjects
}

func NewBpf(cfg *options.BpfConfig) (*BpfTCGeneral, error) {
	tc := &BpfTCGeneral{}

	if err := tc.newBpf(&tc.InfoTcMarkEncrypt, &tc.InfoTcMarkDecrypt, cfg); err != nil {
		return nil, err
	}

	return tc, nil
}

func (tc *BpfTCGeneral) newBpf(encryptInfo *BpfInfo, decryptInfo *BpfInfo, cfg *options.BpfConfig) error {
	generalMapPath := cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	generalFsPath := cfg.BpfFsPath + "/bpf_kmesh_workload/tc/"

	encryptInfo.MapPath = generalMapPath
	encryptInfo.BpfFsPath = generalFsPath
	encryptInfo.Cgroup2Path = cfg.Cgroup2Path

	decryptInfo.MapPath = generalMapPath
	decryptInfo.BpfFsPath = generalFsPath
	decryptInfo.Cgroup2Path = cfg.Cgroup2Path

	if err := os.MkdirAll(generalMapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(generalFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (tc *BpfTCGeneral) loadKmeshTCObjects() (*ebpf.CollectionSpec, *ebpf.CollectionSpec, error) {
	var (
		errTcMarkEncrypt  error
		errTcMarkDecrypt  error
		specTcMarkEncrypt *ebpf.CollectionSpec
		optsTcMarkEncrypt ebpf.CollectionOptions
		specTcMarkDecrypt *ebpf.CollectionSpec
		optsTcMarkDecrypt ebpf.CollectionOptions
	)

	optsTcMarkEncrypt.Maps.PinPath = tc.InfoTcMarkEncrypt.MapPath
	optsTcMarkDecrypt.Maps.PinPath = tc.InfoTcMarkDecrypt.MapPath
	if helper.KernelVersionLowerThan5_13() {
		specTcMarkEncrypt, errTcMarkEncrypt = general.LoadKmeshTcMarkEncryptCompat()
		specTcMarkDecrypt, errTcMarkDecrypt = general.LoadKmeshTcMarkDecryptCompat()
	} else {
		specTcMarkEncrypt, errTcMarkEncrypt = general.LoadKmeshTcMarkEncrypt()
		specTcMarkDecrypt, errTcMarkDecrypt = general.LoadKmeshTcMarkDecrypt()
	}

	if errTcMarkEncrypt != nil {
		return nil, nil, errTcMarkEncrypt
	}

	if errTcMarkDecrypt != nil {
		return nil, nil, errTcMarkDecrypt
	}

	utils.SetMapPinType(specTcMarkEncrypt, ebpf.PinByName)
	utils.SetMapPinType(specTcMarkDecrypt, ebpf.PinByName)
	if err := specTcMarkEncrypt.LoadAndAssign(&tc.KmeshTcMarkEncryptObjects, &optsTcMarkEncrypt); err != nil {
		return nil, nil, err
	}
	if err := specTcMarkDecrypt.LoadAndAssign(&tc.KmeshTcMarkDecryptObjects, &optsTcMarkDecrypt); err != nil {
		return nil, nil, err
	}

	return specTcMarkEncrypt, specTcMarkDecrypt, nil
}

func (tc *BpfTCGeneral) LoadTC() error {
	if tc == nil {
		return nil
	}
	specMarkEncrypt, specMarkDecrypt, err := tc.loadKmeshTCObjects()
	if err != nil {
		return err
	}

	prog := specMarkEncrypt.Programs[constants.TC_MARK_ENCRYPT]
	tc.InfoTcMarkEncrypt.Type = prog.Type
	tc.InfoTcMarkEncrypt.AttachType = prog.AttachType

	prog = specMarkDecrypt.Programs[constants.TC_MARK_DECRYPT]
	tc.InfoTcMarkDecrypt.Type = prog.Type
	tc.InfoTcMarkDecrypt.AttachType = prog.AttachType

	return nil
}

func (tc *BpfTCGeneral) Close() error {
	if tc == nil {
		return nil
	}

	if err := tc.KmeshTcMarkEncryptObjects.Close(); err != nil {
		return err
	}
	if err := tc.KmeshTcMarkDecryptObjects.Close(); err != nil {
		return err
	}

	progVal := reflect.ValueOf(tc.KmeshTcMarkEncryptObjects.KmeshTcMarkEncryptPrograms)
	if err := utils.UnpinPrograms(&progVal); err != nil {
		return err
	}
	progVal = reflect.ValueOf(tc.KmeshTcMarkDecryptObjects.KmeshTcMarkDecryptPrograms)
	if err := utils.UnpinPrograms(&progVal); err != nil {
		return err
	}

	mapVal := reflect.ValueOf(tc.KmeshTcMarkEncryptObjects.KmeshTcMarkEncryptMaps)
	if err := utils.UnpinMaps(&mapVal); err != nil {
		return err
	}
	mapVal = reflect.ValueOf(tc.KmeshTcMarkDecryptObjects.KmeshTcMarkDecryptMaps)
	if err := utils.UnpinMaps(&mapVal); err != nil {
		return err
	}

	return nil
}
