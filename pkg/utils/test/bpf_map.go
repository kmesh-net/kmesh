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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package test

import (
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/rlimit"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/constants"
)

type CleanupFn func()

func InitBpfMap(t *testing.T, config options.BpfConfig) (CleanupFn, *bpf.BpfLoader) {
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

	loader := bpf.NewBpfLoader(&config)

	if config.Mode == constants.AdsMode {
		err = loader.StartAdsMode()
	}
	if config.Mode == constants.WorkloadMode {
		err = loader.StartWorkloadMode()
	}

	if err != nil {
		CleanupBpfMap()
		t.Fatalf("bpf init failed: %v", err)
	}
	return func() {
		loader.Stop()
		CleanupBpfMap()
	}, loader
}

func CleanupBpfMap() {
	err := syscall.Unmount("/mnt/kmesh_cgroup2", 0)
	if err != nil {
		fmt.Println("unmount /mnt/kmesh_cgroup2 error: ", err)
	}
	err = syscall.Unmount("/sys/fs/bpf", 0)
	if err != nil {
		fmt.Println("unmount /sys/fs/bpf error: ", err)
	}
	err = os.RemoveAll("/mnt/kmesh_cgroup2")
	if err != nil {
		fmt.Println("remove /mnt/kmesh_cgroup2 error: ", err)
	}
}

func EqualIp(src [16]byte, dst []byte) bool {
	if dst == nil {
		return false
	}
	size := len(dst)
	if size == 0 {
		return false
	}
	if size != 4 && size != 16 {
		return false
	}

	for i := 0; i < size; i++ {
		if src[i] != dst[i] {
			return false
		}
	}
	return true
}
