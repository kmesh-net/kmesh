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

package test

import (
	"os"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf"
)

type CleanupFn func()

func InitBpfMap(t *testing.T, config options.BpfConfig) (CleanupFn, *bpf.BpfLoader) {
	err := os.MkdirAll("/mnt/kmesh_cgroup2", 0755)
	if err != nil {
		t.Fatalf("Failed to create dir /mnt/kmesh_cgroup2: %v", err)
	}
	err = syscall.Mount("none", "/mnt/kmesh_cgroup2/", "cgroup2", 0, "")
	if err != nil {
		bpf.CleanupBpfMap()
		t.Fatalf("Failed to mount /mnt/kmesh_cgroup2/: %v", err)
	}
	err = syscall.Mount("/sys/fs/bpf", "/sys/fs/bpf", "bpf", 0, "")
	if err != nil {
		bpf.CleanupBpfMap()
		t.Fatalf("Failed to mount /sys/fs/bpf: %v", err)
	}

	if err = rlimit.RemoveMemlock(); err != nil {
		bpf.CleanupBpfMap()
		t.Fatalf("Failed to remove mem limit: %v", err)
	}

	loader := bpf.NewBpfLoader(&config)
	err = loader.Start()
	if err != nil {
		bpf.CleanupBpfMap()
		t.Fatalf("bpf init failed: %v", err)
	}
	return func() {
		loader.Stop()
	}, loader
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

func GetMapCount(kmeshMap *ebpf.Map, t *testing.T) int {
	count := 0
	keySize := int(kmeshMap.KeySize())
	valueSize := int(kmeshMap.ValueSize())
	iter := kmeshMap.Iterate()

	key := make([]byte, keySize)
	value := make([]byte, valueSize)

	for iter.Next(key, value) {
		count++
	}
	assert.Nil(t, iter.Err())
	return count
}
