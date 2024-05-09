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

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf"
)

type CleanupFn func()

func InitBpfMap(t *testing.T) CleanupFn {
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
	config := options.BpfConfig{
		Mode:        "ads",
		BpfFsPath:   "/sys/fs/bpf",
		Cgroup2Path: "/mnt/kmesh_cgroup2",
	}
	loader := bpf.NewBpfLoader(&config)
	err = loader.StartAdsMode()
	if err != nil {
		CleanupBpfMap()
		t.Fatalf("bpf init failed: %v", err)
	}
	return func() {
		loader.Stop()
		CleanupBpfMap()
	}
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
