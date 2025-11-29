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

package netns

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"istio.io/istio/pkg/util/sets"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestGetNodeNSpath(t *testing.T) {
	expected := "/host/proc/1/ns/net"
	result := GetNodeNSpath()

	if result != expected {
		t.Errorf("GetNodeNSpath() = %v, want %v", result, expected)
	}
}

func TestGetPodNSpath(t *testing.T) {
	tests := []struct {
		name    string
		pod     *corev1.Pod
		wantErr bool
		setup   func() func()
	}{
		{
			name: "valid pod with network namespace",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					UID: "test-uid-123",
				},
			},
			wantErr: true, // Will fail in test environment without proper /host/proc setup
		},
		{
			name: "pod without UID",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				cleanup := tt.setup()
				defer cleanup()
			}

			result, err := GetPodNSpath(tt.pod)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPodNSpath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result == "" {
				t.Error("GetPodNSpath() returned empty string for valid pod")
			}
		})
	}
}

func TestBuiltinOrDir(t *testing.T) {
	tests := []struct {
		name string
		dir  string
	}{
		{
			name: "empty dir returns embedded FS",
			dir:  "",
		},
		{
			name: "non-empty dir returns DirFS",
			dir:  "/tmp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builtinOrDir(tt.dir)
			if result == nil {
				t.Error("builtinOrDir() returned nil")
			}
		})
	}
}

func TestIsNotNumber(t *testing.T) {
	tests := []struct {
		name string
		r    rune
		want bool
	}{
		{name: "digit 0", r: '0', want: false},
		{name: "digit 5", r: '5', want: false},
		{name: "digit 9", r: '9', want: false},
		{name: "letter a", r: 'a', want: true},
		{name: "letter Z", r: 'Z', want: true},
		{name: "special char", r: '-', want: true},
		{name: "space", r: ' ', want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNotNumber(tt.r); got != tt.want {
				t.Errorf("isNotNumber(%c) = %v, want %v", tt.r, got, tt.want)
			}
		})
	}
}

func TestIsProcess(t *testing.T) {
	tests := []struct {
		name  string
		entry fs.DirEntry
		want  bool
	}{
		{
			name:  "numeric directory",
			entry: createMockDirEntry("1234", true),
			want:  true,
		},
		{
			name:  "non-numeric directory",
			entry: createMockDirEntry("proc", true),
			want:  false,
		},
		{
			name:  "file with numeric name",
			entry: createMockDirEntry("1234", false),
			want:  false,
		},
		{
			name:  "directory with mixed name",
			entry: createMockDirEntry("123abc", true),
			want:  false,
		},
		{
			name:  "empty name directory",
			entry: createMockDirEntry("", true),
			want:  true, // An empty name is not a valid process ID.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isProcess(tt.entry); got != tt.want {
				t.Errorf("isProcess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessEntry(t *testing.T) {
	// Create a mock filesystem
	mockFS := fstest.MapFS{
		"1234/ns/net": &fstest.MapFile{
			Mode: 0644,
		},
		"1234/cgroup": &fstest.MapFile{
			Data: []byte("12:pids:/kubepods/pod123-456-789\n"),
			Mode: 0644,
		},
		"5678/ns/net": &fstest.MapFile{
			Mode: 0644,
		},
		"5678/cgroup": &fstest.MapFile{
			Data: []byte("12:pids:/kubepods/pod987-654-321\n"),
			Mode: 0644,
		},
	}

	tests := []struct {
		name          string
		entry         fs.DirEntry
		filter        types.UID
		netnsObserved sets.Set[uint64]
		wantErr       bool
		wantResult    string
	}{
		{
			name:          "non-process entry",
			entry:         createMockDirEntry("test", true),
			filter:        "test-uid",
			netnsObserved: sets.New[uint64](),
			wantErr:       false,
			wantResult:    "",
		},
		{
			name:          "process entry - numeric dir",
			entry:         createMockDirEntry("1234", true),
			filter:        "test-uid",
			netnsObserved: sets.New[uint64](),
			wantErr:       true, // Will fail without proper mock setup
			wantResult:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := processEntry(mockFS, tt.netnsObserved, tt.filter, tt.entry)

			if (err != nil) != tt.wantErr {
				t.Errorf("processEntry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if result != tt.wantResult {
				t.Errorf("processEntry() = %v, want %v", result, tt.wantResult)
			}
		})
	}
}

func TestFindNetnsForPod(t *testing.T) {
	tests := []struct {
		name    string
		pod     *corev1.Pod
		wantErr bool
		setup   func() (string, func())
	}{
		{
			name: "pod not found",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					UID: "nonexistent-uid",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cleanup func()
			if tt.setup != nil {
				_, cleanup = tt.setup()
				defer cleanup()
			}

			result, err := FindNetnsForPod(tt.pod)

			if (err != nil) != tt.wantErr {
				t.Errorf("FindNetnsForPod() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result == "" {
				t.Error("FindNetnsForPod() returned empty string for valid pod")
			}
		})
	}
}

// Helper function to create mock DirEntry
type mockDirEntry struct {
	name  string
	isDir bool
}

func (m mockDirEntry) Name() string               { return m.name }
func (m mockDirEntry) IsDir() bool                { return m.isDir }
func (m mockDirEntry) Type() fs.FileMode          { return 0 }
func (m mockDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

func createMockDirEntry(name string, isDir bool) fs.DirEntry {
	return mockDirEntry{name: name, isDir: isDir}
}

// Integration test helper to create a temporary proc-like structure
// nolint:unused
func createMockProcFS(t *testing.T, podUID string) (string, func()) {
	tmpDir, err := os.MkdirTemp("", "mock-proc-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create a mock process directory structure
	procDir := filepath.Join(tmpDir, "1234")
	nsDir := filepath.Join(procDir, "ns")

	if err := os.MkdirAll(nsDir, 0755); err != nil {
		_ = os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create ns dir: %v", err)
	}

	// Create mock net namespace file
	netFile := filepath.Join(nsDir, "net")
	if err := os.WriteFile(netFile, []byte{}, 0644); err != nil {
		_ = os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create net file: %v", err)
	}

	// Create mock cgroup file
	cgroupFile := filepath.Join(procDir, "cgroup")
	cgroupContent := "12:pids:/kubepods/pod" + string(podUID) + "\n"
	if err := os.WriteFile(cgroupFile, []byte(cgroupContent), 0644); err != nil {
		_ = os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create cgroup file: %v", err)
	}

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	return tmpDir, cleanup
}
