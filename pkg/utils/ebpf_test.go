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

//go:build linux
// +build linux

package utils

import (
	"fmt"
	"os"
	"testing"
)

// countOpenFDs returns the number of open file descriptors for the current process.
// It skips the test if /proc for the current process cannot be read.
func countOpenFDs(t *testing.T) int {
	t.Helper()
	pid := os.Getpid()
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Skipf("skipping FD leak test: failed to read /proc/%d/fd: %v", pid, err)
	}
	return len(fds)
}

func TestGetProgramByName_FDLeak(t *testing.T) {
	initialFDs := countOpenFDs(t)
	t.Logf("Initial open File Descriptors: %d", initialFDs)

	// Call the function in a loop.
	// Searching for a non-existent program forces it to iterate through ALL
	// loaded BPF programs, which would previously leak an FD for every single one.
	for i := 0; i < 10; i++ {
		_, err := GetProgramByName("non_existent_fake_prog_12345")
		if err == nil {
			t.Fatal("expected error for non-existent program, got nil")
		}
	}

	finalFDs := countOpenFDs(t)
	t.Logf("Final open File Descriptors: %d", finalFDs)

	if finalFDs > initialFDs+10 {
		t.Fatalf("FD LEAK DETECTED! Started with %d FDs, ended with %d FDs.", initialFDs, finalFDs)
	}
	t.Log("No leak detected.")
}

func TestGetMapByName_FDLeak(t *testing.T) {
	initialFDs := countOpenFDs(t)
	t.Logf("Initial open File Descriptors: %d", initialFDs)

	// Call the function in a loop.
	// Searching for a non-existent map forces it to iterate through ALL
	// loaded BPF maps, which would previously leak an FD for every single one.
	for i := 0; i < 10; i++ {
		_, err := GetMapByName("non_existent_fake_map_12345")
		if err == nil {
			t.Fatal("expected error for non-existent map, got nil")
		}
	}

	finalFDs := countOpenFDs(t)
	t.Logf("Final open File Descriptors: %d", finalFDs)

	if finalFDs > initialFDs+10 {
		t.Fatalf("FD LEAK DETECTED! Started with %d FDs, ended with %d FDs.", initialFDs, finalFDs)
	}
	t.Log("No leak detected.")
}
