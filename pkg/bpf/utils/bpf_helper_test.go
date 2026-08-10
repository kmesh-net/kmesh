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

package utils

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"istio.io/istio/pkg/log"
	"kmesh.net/kmesh/pkg/constants"
)

func GetProgramCount(name string) (int, error) {
	var id ebpf.ProgramID
	count := 0

	for {
		nextID, err := ebpf.ProgramGetNextID(id)
		if errors.Is(err, syscall.ENOENT) {
			break
		}
		if err != nil {
			return 0, err
		}

		prog, err := ebpf.NewProgramFromID(nextID)
		if err != nil {
			return 0, err
		}

		info, err := prog.Info()
		prog.Close()
		if err != nil {
			return 0, err
		}

		if info.Name == name {
			count++
		}

		id = nextID
	}

	return count, nil
}

func Test_BpfProgUpdate(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("mount")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("Failed execute command 'mount': %v", err)
	}

	if !bytes.Contains(out, []byte("type bpf")) {
		if err := syscall.Mount("/sys/fs/bpf", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
			t.Fatalf("Failed to mount /sys/fs/bpf: %v", err)
		}

		defer func() {
			err = syscall.Unmount(constants.BpfFsPath, 0)
			if err != nil {
				log.Errorf("unmount /sys/fs/bpf error: %v", err)
			}
		}()
	}

	if !bytes.Contains(out, []byte("/mnt/kmesh_cgroup2")) {
		if err := os.MkdirAll("/mnt/kmesh_cgroup2", 0755); err != nil {
			t.Fatalf("Failed to create /mnt/kmesh_cgroup2/: %v", err)
		}
		if err := syscall.Mount("none", "/mnt/kmesh_cgroup2/", "cgroup2", 0, ""); err != nil {
			t.Fatalf("Failed to mount /mnt/kmesh_cgroup2/: %v", err)
		}

		defer func() {
			err := syscall.Unmount(constants.Cgroup2Path, 0)
			if err != nil {
				log.Errorf("unmount /mnt/kmesh_cgroup2 error: %v", err)
			}
		}()
	}

	pinPath := "/sys/fs/bpf/kmesh_test_prog"
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:       "test_prog",
		Type:       ebpf.CGroupSockAddr,
		AttachType: ebpf.AttachCGroupInet4Connect,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "GPL",
	})

	if err != nil {
		t.Fatalf("BpfProgUpdate failed: %v", err)
	}

	cgopt := link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: prog,
	}

	testLink, err := link.AttachCgroup(cgopt)

	if err != nil {
		t.Fatalf("BpfProgUpdate failed: %v", err)
	}

	prog.Close()

	defer testLink.Close()

	err = testLink.Pin(pinPath)

	if err != nil {
		t.Fatalf("BpfProgUpdate failed: %v", err)
	}
	defer testLink.Unpin()

	cgopt.Program, err = ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:       "test_prog",
		Type:       ebpf.CGroupSockAddr,
		AttachType: ebpf.AttachCGroupInet4Connect,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "GPL",
	})

	if err != nil {
		t.Fatalf("Error when creating second program: %v", err)
	}

	defer cgopt.Program.Close()

	if _, err = BpfProgUpdate(pinPath, cgopt); err != nil {
		t.Fatalf("BpfProgUpdate failed: %v", err)
	}

	count, err := GetProgramCount("test_prog")

	if err != nil {
		t.Fatalf("Error when checking for program count")
	}

	assert.Equal(t, count, 1)
}
