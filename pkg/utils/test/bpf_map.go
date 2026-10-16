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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf"
)

type CleanupFn func()

// lookupMountFstype reports whether target currently has a mount and, if so,
// its filesystem type (parsed from /proc/self/mountinfo).
func lookupMountFstype(target string) (bool, string) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, ""
	}
	target = filepath.Clean(target)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(parts[0])
		if len(fields) < 5 {
			continue
		}
		if strings.ReplaceAll(fields[4], `\040`, " ") != target {
			continue
		}
		tail := strings.Fields(parts[1])
		if len(tail) == 0 {
			return true, ""
		}
		return true, tail[0]
	}
	return false, ""
}

// mountWithRetry mounts source at target. On EBUSY it lazily detaches the
// leftover mount only if that mount has the SAME filesystem type we are about
// to mount (i.e. a stale mount from a previous test run) and retries. Mounts of
// any other filesystem type are never touched, so shared host mounts stay safe.
func mountWithRetry(source, target, fstype string) error {
	var err error
	for i := 0; i < 5; i++ {
		err = syscall.Mount(source, target, fstype, 0, "")
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EBUSY) {
			return err
		}
		if ok, current := lookupMountFstype(target); !ok || current != fstype {
			return err
		}
		if uerr := syscall.Unmount(target, syscall.MNT_DETACH); uerr != nil {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return err
}

func InitBpfMap(t *testing.T, config options.BpfConfig) (CleanupFn, *bpf.BpfLoader) {
	err := os.MkdirAll("/mnt/kmesh_cgroup2", 0755)
	if err != nil {
		t.Fatalf("Failed to create dir /mnt/kmesh_cgroup2: %v", err)
	}
	err = mountWithRetry("none", "/mnt/kmesh_cgroup2/", "cgroup2")
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
