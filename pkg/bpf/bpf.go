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
// #include "cluster/cluster.pb-c.h"
import "C"
import (
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/version"
)

var (
	log  = logger.NewLoggerField("pkg/bpf")
	hash = fnv.New32a()
)

type BpfInfo struct {
	MapPath     string
	BpfFsPath   string
	Cgroup2Path string

	Type       ebpf.ProgramType
	AttachType ebpf.AttachType
}

type BpfLoader struct {
	config *options.BpfConfig

	obj         *BpfKmesh
	workloadObj *BpfKmeshWorkload
	bpfLogLevel *ebpf.Map
	versionMap  *ebpf.Map
}

func NewBpfLoader(config *options.BpfConfig) *BpfLoader {
	return &BpfLoader{
		config:     config,
		versionMap: NewVersionMap(config),
	}
}

func (l *BpfLoader) StartAdsMode() (err error) {
	var ve *ebpf.VerifierError
	if l.obj, err = NewBpfKmesh(l.config); err != nil {
		return err
	}

	defer func() {
		if err != nil {
			l.Stop()
		}
	}()

	if err = l.obj.Load(); err != nil {
		if errors.As(err, &ve) {
			return fmt.Errorf("bpf Load failed: %+v", ve)
		}
		return fmt.Errorf("bpf Load failed: %v", err)
	}

	if err = l.obj.Attach(); err != nil {
		return fmt.Errorf("bpf Attach failed, %s", err)
	}

	if err = l.obj.ApiEnvCfg(); err != nil {
		return fmt.Errorf("api env config failed, %s", err)
	}

	l.bpfLogLevel = l.obj.SockConn.BpfLogLevel
	ret := C.deserial_init()
	if ret != 0 {
		l.Stop()
		return fmt.Errorf("deserial_init failed:%v", ret)
	}
	return nil
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

func (l *BpfLoader) Start(config *options.BpfConfig) error {
	var err error

	if l.versionMap == nil {
		return fmt.Errorf("NewVersionMap failed")
	}

	if config.AdsEnabled() {
		if err = l.StartAdsMode(); err != nil {
			return err
		}
	} else if config.WdsEnabled() {
		if err = l.StartWorkloadMode(); err != nil {
			return err
		}
	}

	if config.EnableMda {
		if err = StartMda(); err != nil {
			return err
		}
	}

	if GetStartType() == Restart {
		log.Infof("bpf load from last pinPath")
	}
	return nil
}

func (l *BpfLoader) GetBpfKmeshWorkload() *BpfKmeshWorkload {
	if l == nil {
		return nil
	}
	return l.workloadObj
}

func (l *BpfLoader) GetBpfLogLevel() *ebpf.Map {
	if l == nil {
		return nil
	}
	return l.bpfLogLevel
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
	if GetExitType() == Restart {
		log.Infof("kmesh restart, not clean bpf map and prog")
		return
	}

	closeMap(l.versionMap)

	if l.config.AdsEnabled() {
		C.deserial_uninit()
		if err = l.obj.Detach(); err != nil {
			CleanupBpfMap()
			log.Errorf("failed detach when stop kmesh, err:%s", err)
			return
		}
	} else if l.config.WdsEnabled() {
		if err = l.workloadObj.Detach(); err != nil {
			CleanupBpfMap()
			log.Errorf("failed detach when stop kmesh, err:%s", err)
			return
		}
	}

	if l.config.EnableMda {
		if err = StopMda(); err != nil {
			CleanupBpfMap()
			log.Errorf("failed disable mda when stop kmesh, err:%s", err)
			return
		}
	}
	CleanupBpfMap()
}

func NewVersionMap(config *options.BpfConfig) *ebpf.Map {
	var versionPath string
	var versionMap *ebpf.Map
	if config.AdsEnabled() {
		versionPath = filepath.Join(config.BpfFsPath, constants.VersionPath)
	} else if config.WdsEnabled() {
		versionPath = filepath.Join(config.BpfFsPath, constants.WorkloadVersionPath)
	}

	versionMapPinPath := filepath.Join(versionPath, "kmesh_version")
	_, err := os.Stat(versionPath)
	if err == nil {
		versionMap = recoverVersionMap(versionMapPinPath)
		if versionMap != nil {
			SetStartStatus(versionMap)
		}
	}

	switch GetStartType() {
	case Restart:
		return versionMap
	case Update:
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
	SetStartType(Normal)
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

func getOldVersionFromMap(m *ebpf.Map, key uint32) uint32 {
	var value uint32
	err := m.Lookup(&key, &value)
	if err != nil {
		log.Errorf("lookup failed: %v", err)
		return value
	}
	return value
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
	var err error
	err = m.Unpin()
	if err != nil {
		log.Errorf("Failed to unpin kmesh_version: %v", err)
	}

	err = m.Close()
	if err != nil {
		log.Errorf("Failed to close kmesh_version: %v", err)
	}

	log.Infof("cleaned kmesh_version map")
}
