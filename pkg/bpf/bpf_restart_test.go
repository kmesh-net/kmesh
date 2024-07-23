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

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"

	"kmesh.net/kmesh/daemon/options"
)

func TestRestart(t *testing.T) {
	t.Run("TestRestartnewStart", func(t *testing.T) {
		runTestNormal(t)
	})
	t.Run("TestRestartReload", func(t *testing.T) {
		runTestRestart(t)
	})
}

func setDir(t *testing.T) options.BpfConfig {
	CleanupBpfMap()
	err := os.MkdirAll("/mnt/kmesh_cgroup2", 0755)
	if err != nil {
		t.Fatalf("Failed to create dir /mnt/kmesh_cgroup2: %v", err)
	}
	err = syscall.Mount("none", "/mnt/kmesh_cgroup2/", "cgroup2", 0, "")
	if err != nil {
		CleanupBpfMap()
		t.Fatalf("Failed to mount /mnt/kmesh_cgroup2/: %v", err)
	}
	err = syscall.Mount("/sys/fs/bpf", "/sys/fs/bpf", "bpf", 0, "")
	if err != nil {
		CleanupBpfMap()
		t.Fatalf("Failed to mount /sys/fs/bpf: %v", err)
	}

	if err = rlimit.RemoveMemlock(); err != nil {
		CleanupBpfMap()
		t.Fatalf("Failed to remove mem limit: %v", err)
	}

	return options.BpfConfig{
		Mode:        "workload",
		BpfFsPath:   "/sys/fs/bpf",
		Cgroup2Path: "/mnt/kmesh_cgroup2",
	}
}

// Test Kmesh Normal
func runTestNormal(t *testing.T) {
	config := setDir(t)

	bpfLoader := NewBpfLoader(&config)
	if err := bpfLoader.Start(&config); err != nil {
		assert.ErrorIsf(t, err, nil, "bpfLoader start failed %v", err)
	}
	assert.Equal(t, Normal, GetKmeshStatus(), "set kmesh start status failed")
	SetCloseStatus()
	assert.Equal(t, Normal, GetKmeshStatus(), "set kmesh close status failed")
	bpfLoader.Stop()
}

// Test Kmesh Restart Normal
func runTestRestart(t *testing.T) {
	var versionPath string
	config := setDir(t)
	bpfLoader := NewBpfLoader(&config)
	if err := bpfLoader.Start(&config); err != nil {
		assert.ErrorIsf(t, err, nil, "bpfLoader start failed %v", err)
	}
	assert.Equal(t, Normal, GetKmeshStatus(), "set kmesh start status:Normal failed")
	SetKmeshStatus(Restart)
	bpfLoader.Stop()
	assert.Equal(t, Restart, GetKmeshStatus(), "set kmesh close status:Restart failed")

	if config.AdsEnabled() {
		versionPath = filepath.Join(config.BpfFsPath + "/bpf_kmesh/map/")
	} else if config.WdsEnabled() {
		versionPath = filepath.Join(config.BpfFsPath + "/bpf_kmesh_workload/map/")
	}
	_, err := os.Stat(versionPath)
	assert.ErrorIsf(t, err, nil, "bpfLoader Stop failed,versionPath is not exist: %v", err)

	// Restart
	bpfLoader = NewBpfLoader(&config)
	if err := bpfLoader.Start(&config); err != nil {
		assert.ErrorIsf(t, err, nil, "bpfLoader start failed %v", err)
	}
	assert.Equal(t, Restart, GetKmeshStatus(), "set kmesh start status:Restart failed")
	SetKmeshStatus(Normal)
	bpfLoader.Stop()
}
