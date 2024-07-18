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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/version"
)

var log = logger.NewLoggerField("pkg/bpf")

type BpfInfo struct {
	MapPath          string
	BpfFsPath        string
	BpfVerifyLogSize int
	Cgroup2Path      string

	Type       ebpf.ProgramType
	AttachType ebpf.AttachType
}

type BpfLoader struct {
	config *options.BpfConfig

	obj         *BpfKmesh
	workloadObj *BpfKmeshWorkload
	bpfLogLevel *ebpf.Map
	StatusMap   *ebpf.Map
}

func NewBpfLoader(config *options.BpfConfig) *BpfLoader {
	return &BpfLoader{
		config:    config,
		StatusMap: NewVersionMap(config),
	}
}

func (l *BpfLoader) StartAdsMode() (err error) {
	if l.obj, err = NewBpfKmesh(l.config); err != nil {
		return err
	}

	defer func() {
		if err != nil {
			l.Stop()
		}
	}()

	if err = l.obj.Load(); err != nil {
		return fmt.Errorf("bpf Load failed, %s", err)
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

	if err = rlimit.RemoveMemlock(); err != nil {
		return err
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

	if GetKmeshStartStatus() == Restart {
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
	if GetKmeshStartStatus() == Restart {
		log.Infof("kmesh restart, not clean bpf map and prog")
		return
	}

	Close(l.StatusMap)

	if l.config.AdsEnabled() {
		C.deserial_uninit()
		if err = l.obj.Detach(); err != nil {
			log.Errorf("failed detach when stop kmesh, err:%s", err)
			return
		}
	} else if l.config.WdsEnabled() {
		if err = l.workloadObj.Detach(); err != nil {
			log.Errorf("failed detach when stop kmesh, err:%s", err)
			return
		}
	}

	if l.config.EnableMda {
		if err = StopMda(); err != nil {
			log.Errorf("failed disable mda when stop kmesh, err:%s", err)
			return
		}
	}
	CleanupBpfMap()
}

func NewVersionMap(config *options.BpfConfig) *ebpf.Map {
	var versionPath string
	if config.AdsEnabled() {
		versionPath = filepath.Join(config.BpfFsPath + "/bpf_kmesh/map/")
	} else if config.WdsEnabled() {
		versionPath = filepath.Join(config.BpfFsPath + "/bpf_kmesh_workload/map/")
	}

	_, err := os.Stat(versionPath)
	if err == nil {
		m := RecoverVersionMap(config, versionPath)
		if m != nil {
			SetStartStatus(m)
			return m
		}
	}

	mapSpec := &ebpf.MapSpec{
		Name:       "kmesh_version",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  16,
		MaxEntries: 1,
	}
	m, err := ebpf.NewMap(mapSpec)
	if err != nil {
		log.Errorf("Create kmesh_version map failed, err is %v", err)
	}

	if err := os.MkdirAll(versionPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		log.Errorf("mkdir failed %v", err)
		return nil
	}

	err = m.Pin(filepath.Join(versionPath + "kmesh_version"))
	if err != nil {
		log.Errorf("kmesh_version pin failed: %v", err)
		return nil
	}

	storeVersionInfo(m)
	SetKmeshStartStatus(NewStart)
	return m
}

func storeVersionInfo(versionMap *ebpf.Map) {
	key := uint32(0)
	var value [16]byte
	copy(value[:], version.Get().GitVersion)
	if err := versionMap.Put(&key, &value); err != nil {
		log.Errorf("Add Version Map failed, err is %v", err)
	}
}

func GetMap(m *ebpf.Map, key uint32) [16]byte {
	var valueBytes [16]byte
	err := m.Lookup(&key, &valueBytes)
	if err != nil {
		log.Errorf("lookup failed: %v", err)
		return [16]byte{}
	}
	return valueBytes
}

func RecoverVersionMap(config *options.BpfConfig, versionPath string) *ebpf.Map {
	opts := &ebpf.LoadPinOptions{
		ReadOnly:  false,
		WriteOnly: false,
		Flags:     0,
	}

	versionMap, err := ebpf.LoadPinnedMap(versionPath+"kmesh_version", opts)
	if err != nil {
		log.Debugf("kmesh version map LoadPinnedMap failed: %v, Start normal", err)
		return nil
	}
	log.Debugf("RecoverVersionMap success")

	return versionMap
}

func Close(m *ebpf.Map) {
	var err error
	err = m.Unpin()
	if err != nil {
		log.Errorf("Failed to Unpin kmesh_version :%v", err)
	}

	err = m.Close()
	if err != nil {
		log.Errorf("Failed to Close kmesh_version :%v", err)
	}

	log.Infof("Clean kmesh_version map and bpf prog")
}
