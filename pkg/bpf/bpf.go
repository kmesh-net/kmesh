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

package bpf

// #cgo pkg-config: api-v2-c
// #include "deserialization_to_bpf_map.h"
import "C"
import (
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/ads"
	"kmesh.net/kmesh/pkg/bpf/restart"
	"kmesh.net/kmesh/pkg/bpf/workload"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/version"
)

var (
	log  = logger.NewLoggerScope("bpf")
	hash = fnv.New32a()
)

type BpfLoader struct {
	config *options.BpfConfig

	obj         *ads.BpfAds
	workloadObj *workload.BpfWorkload
	kmeshConfig *ebpf.Map
	versionMap  *ebpf.Map
}

func NewBpfLoader(config *options.BpfConfig) *BpfLoader {
	return &BpfLoader{
		config:     config,
		versionMap: NewVersionMap(config),
	}
}

func StartMda() error {
	cmd := exec.Command("mdacore", "enable")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(strings.Replace(string(output), "\n", " ", -1))
		return err
	}

	log.Info(strings.Replace(string(output), "\n", " ", -1))
	return nil
}

func (l *BpfLoader) Start() error {
	var err error
	if l.config.KernelNativeEnabled() {
		if l.obj, err = ads.NewBpfAds(l.config); err != nil {
			return err
		}
		if err = l.obj.Start(); err != nil {
			return err
		}
		l.kmeshConfig = l.obj.GetKmeshConfigMap()
	} else if l.config.DualEngineEnabled() {
		if l.workloadObj, err = workload.NewBpfWorkload(l.config); err != nil {
			return err
		}
		if err = l.workloadObj.Start(); err != nil {
			return err
		}
		l.kmeshConfig = l.workloadObj.GetKmeshConfigMap()
	}

	// TODO: move start mds out of bpf loader
	if l.config.EnableMda {
		if err = StartMda(); err != nil {
			return err
		}
	}

	if restart.GetStartType() == restart.Restart {
		log.Infof("bpf load from last pinPath")
	}
	return nil
}

func (l *BpfLoader) GetBpfKmesh() *ads.BpfAds {
	if l == nil {
		return nil
	}
	return l.obj
}

func (l *BpfLoader) GetBpfWorkload() *workload.BpfWorkload {
	if l == nil {
		return nil
	}
	return l.workloadObj
}

func (l *BpfLoader) GetKmeshConfig() *ebpf.Map {
	if l == nil {
		return nil
	}
	return l.kmeshConfig
}

func StopMda() error {
	cmd := exec.Command("mdacore", "disable")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(strings.Replace(string(output), "\n", " ", -1))
		return err
	}

	log.Info(strings.Replace(string(output), "\n", " ", -1))
	return nil
}

func (l *BpfLoader) Stop() {
	var err error
	if restart.GetExitType() == restart.Restart && l.config.DualEngineEnabled() {
		C.deserial_uninit(true)
		log.Infof("kmesh restart, not clean bpf map and prog")
		return
	}

	closeMap(l.versionMap)

	if l.config.KernelNativeEnabled() {
		if err = l.obj.Stop(); err != nil {
			CleanupBpfMap()
			log.Errorf("failed stop bpf, err: %v", err)
			return
		}
	} else if l.config.DualEngineEnabled() {
		if err = l.workloadObj.Stop(); err != nil {
			CleanupBpfMap()
			log.Errorf("failed stop bpf workload, err: %v", err)
			return
		}
	}

	if l.config.EnableMda {
		if err = StopMda(); err != nil {
			log.Errorf("failed disable mda when stop kmesh, err:%s", err)
		}
	}

	CleanupBpfMap()
}

func NewVersionMap(config *options.BpfConfig) *ebpf.Map {
	var versionPath string
	var versionMap *ebpf.Map
	if config.KernelNativeEnabled() {
		versionPath = filepath.Join(config.BpfFsPath, constants.VersionPath)
	} else if config.DualEngineEnabled() {
		versionPath = filepath.Join(config.BpfFsPath, constants.WorkloadVersionPath)
	}

	versionMapPinPath := filepath.Join(versionPath, "kmesh_version")
	_, err := os.Stat(versionPath)
	if err == nil {
		versionMap = recoverVersionMap(versionMapPinPath)
		if versionMap != nil {
			restart.SetStartStatus(versionMap)
		}
	}

	switch restart.GetStartType() {
	case restart.Restart:
		return versionMap
	case restart.Update:
		// TODO : update mode has not been fully developed and is currently consistent with normal mode
		log.Warnf("Update mode support is under development, Will be started in Normal mode.")
	default:
	}

	// Make sure the directory about to use is clean
	err = os.RemoveAll(versionPath)
	if err != nil {
		log.Errorf("Clean bpf maps and progs failed, err is:%v", err)
		return nil
	}

	mapSpec := &ebpf.MapSpec{
		Name:       "kmesh_version",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	m, err := ebpf.NewMap(mapSpec)
	if err != nil {
		log.Errorf("Create kmesh_version map failed, err is %v", err)
		return nil
	}

	if err := os.MkdirAll(versionPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		log.Errorf("mkdir failed %v", err)
		return nil
	}

	err = m.Pin(versionMapPinPath)
	if err != nil {
		log.Errorf("kmesh_version pin failed: %v", err)
		return nil
	}

	storeVersionInfo(m)
	log.Infof("kmesh start with Normal")
	restart.SetStartType(restart.Normal)
	return m
}

func storeVersionInfo(versionMap *ebpf.Map) {
	key := uint32(0)
	var value uint32
	hash.Reset()
	hash.Write([]byte(version.Get().GitVersion))
	value = hash.Sum32()
	if err := versionMap.Put(&key, &value); err != nil {
		log.Errorf("Add Version Map failed, err is %v", err)
	}
}

func recoverVersionMap(pinPath string) *ebpf.Map {
	opts := &ebpf.LoadPinOptions{
		ReadOnly:  false,
		WriteOnly: false,
		Flags:     0,
	}

	versionMap, err := ebpf.LoadPinnedMap(pinPath, opts)
	if err != nil {
		log.Infof("kmesh version map loadfailed: %v, start normally", err)

		return nil
	}
	log.Debugf("recoverVersionMap success")

	return versionMap
}

func closeMap(m *ebpf.Map) {
	if m == nil {
		return
	}

	if err := m.Unpin(); err != nil {
		log.Errorf("Failed to unpin kmesh_version: %v", err)
	}

	if err := m.Close(); err != nil {
		log.Errorf("Failed to close kmesh_version: %v", err)
	}

	log.Infof("cleaned kmesh_version map")
}

func CleanupBpfMap() {
	err := syscall.Unmount(constants.Cgroup2Path, 0)
	if err != nil {
		log.Errorf("unmount /mnt/kmesh_cgroup2 error: %v", err)
	}
	err = syscall.Unmount(constants.BpfFsPath, 0)
	if err != nil {
		log.Errorf("unmount /sys/fs/bpf error: %v", err)
	}
	err = os.RemoveAll(constants.Cgroup2Path)
	if err != nil {
		log.Errorf("remove /mnt/kmesh_cgroup2 error: %v", err)
	}
	log.Info("cleanup bpf map success")
}
