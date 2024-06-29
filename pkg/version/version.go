/*
 * Copyright 2024 The Kmesh Authors.
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
 * Create: 2024-5-23
 */
package version

import (
	"fmt"
	"os"
	"runtime"
	"syscall"

	"github.com/cilium/ebpf"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	NewStart = iota
	Restart
	Update
	Reload
)

const (
	pkgSubsys = "version"
)

var log = logger.NewLoggerField(pkgSubsys)

var (
	gitVersion   = "v0.0.0-master"
	gitCommit    = "unknown" // sha1 from git, output of $(git rev-parse HEAD)
	gitTreeState = "unknown" // state of git tree, either "clean" or "dirty"

	buildDate = "unknown" // build date in ISO8601 format, output of $(date -u +'%Y-%m-%dT%H:%M:%SZ')

)

// Info contains versioning information.
type Info struct {
	GitVersion   string `json:"gitVersion"`
	GitCommit    string `json:"gitCommit"`
	GitTreeState string `json:"gitTreeState"`
	BuildDate    string `json:"buildDate"`
	GoVersion    string `json:"goVersion"`
	Compiler     string `json:"compiler"`
	Platform     string `json:"platform"`
}

// String returns a Go-syntax representation of the Info.
func (info Info) String() string {
	return fmt.Sprintf("%#v", info)
}

// Get returns the overall codebase version. It's for detecting
// what code a binary was built from.
func Get() Info {
	return Info{
		GitVersion:   gitVersion,
		GitCommit:    gitCommit,
		GitTreeState: gitTreeState,
		BuildDate:    buildDate,
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

func NewVersionMap(configs *options.BootstrapConfigs) *ebpf.Map {
	var versionPath string
	m := RecoverMap(configs.BpfConfig)
	if m != nil {
		*configs.Status = KmeshStartStatus(m)
		return m
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

	if configs.BpfConfig.AdsEnabled() {
		versionPath = configs.BpfConfig.BpfFsPath + "/bpf_kmesh/map/"
	} else if configs.BpfConfig.WdsEnabled() {
		versionPath = configs.BpfConfig.BpfFsPath + "/bpf_kmesh_workload/map/"
	}

	if err := os.MkdirAll(versionPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		log.Errorf("mkdir failed %v", err)
		return nil
	}

	err = m.Pin(versionPath + "kmesh_version")
	if err != nil {
		log.Errorf("kmesh_version failed to pin: %v", err)
		return nil
	}

	Put(m)
	*configs.Status = NewStart
	return m
}

func Put(versionMap *ebpf.Map) {
	key := uint32(0)
	var value [16]byte
	copy(value[:], gitVersion)
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

func KmeshStartStatus(versionMap *ebpf.Map) int {
	var GitVersion [16]byte
	oldGitVersion := GetMap(versionMap, 0)
	copy(GitVersion[:], gitVersion)
	log.Debugf("oldGitVersion:%v;GitVersion:%v", oldGitVersion, GitVersion)
	if GitVersion == oldGitVersion {
		return Reload
	}
	return Update
}

func RecoverMap(config *options.BpfConfig) *ebpf.Map {
	var versionPath string
	opts := &ebpf.LoadPinOptions{
		ReadOnly:  false,
		WriteOnly: false,
		Flags:     0,
	}

	if config.AdsEnabled() {
		versionPath = config.BpfFsPath + "/bpf_kmesh/map/kmesh_version"
	} else if config.WdsEnabled() {
		versionPath = config.BpfFsPath + "/bpf_kmesh_workload/map/kmesh_version"
	}

	versionMap, err := ebpf.LoadPinnedMap(versionPath, opts)
	if err != nil {
		log.Debugf("kmesh version map LoadPinnedMap failed: %v, Start normal", err)
		return nil
	}
	log.Debugf("RecoverMap success")

	return versionMap
}

func Close(m *ebpf.Map) {
	m.Unpin()
	m.Close()

	log.Infof("Close map version")
}
