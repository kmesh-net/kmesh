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
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/factory"
	"kmesh.net/kmesh/pkg/bpf/restart"
	"kmesh.net/kmesh/pkg/constants"
)

func TestUpdateKmeshConfigMap(t *testing.T) {
	config := setDirDualEngine(t)
	bpfLoader := NewBpfLoader(&config)
	if err := bpfLoader.Start(); err != nil {
		assert.ErrorIsf(t, err, nil, "bpfLoader start failed %v", err)
	}
	bpfConfig := factory.GlobalBpfConfig{
		BpfLogLevel:      uint32(3),
		NodeIP:           [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 172, 18, 0, 3},
		PodGateway:       [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 244, 0, 1},
		AuthzOffload:     uint32(1),
		EnableMonitoring: uint32(1),
	}
	err := bpfLoader.UpdateKmeshConfigMap(bpfConfig)
	assert.NoError(t, err)
	got := bpfLoader.GetKmeshConfigMap()
	assert.Equal(t, bpfConfig, got)
	restart.SetExitType(restart.Normal)
	bpfLoader.Stop()
}

func TestRestart(t *testing.T) {
	t.Run("new start DualEngine", func(t *testing.T) {
		runTestNormalDualEngine(t)
	})
	t.Run("new start KernelNative", func(t *testing.T) {
		runTestNormalKernelNative(t)
	})
	t.Run("restart DualEngine", func(t *testing.T) {
		runTestRestartDualEngine(t)
	})
	t.Run("restart KernelNative", func(t *testing.T) {
		runTestRestartKernelNative(t)
	})
}

func setDir() (err error) {
	defer func() {
		if err != nil {
			CleanupBpfMap()
		}
	}()

	if err = os.MkdirAll("/mnt/kmesh_cgroup2", 0755); err != nil {
		return fmt.Errorf("Failed to create dir /mnt/kmesh_cgroup2: %v", err)
	}

	if err = syscall.Mount("none", "/mnt/kmesh_cgroup2/", "cgroup2", 0, ""); err != nil {
		return fmt.Errorf("Failed to mount /mnt/kmesh_cgroup2/: %v", err)
	}
	if err = syscall.Mount("/sys/fs/bpf", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		return fmt.Errorf("Failed to mount /sys/fs/bpf: %v", err)
	}

	if err = rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("Failed to remove mem limit: %v", err)
	}
	return nil
}

func NormalStart(t *testing.T, config options.BpfConfig) {
	bpfLoader := NewBpfLoader(&config)
	if err := bpfLoader.Start(); err != nil {
		assert.ErrorIsf(t, err, nil, "bpfLoader start failed %v", err)
	}
	assert.Equal(t, restart.Normal, restart.GetStartType(), "set kmesh start status failed")
	restart.SetExitType(restart.Normal)
	bpfLoader.Stop()
}

func setDirDualEngine(t *testing.T) options.BpfConfig {
	if err := setDir(); err != nil {
		t.Fatalf("setDir Failed: %v", err)
	}

	return options.BpfConfig{
		Mode:        constants.DualEngineMode,
		BpfFsPath:   "/sys/fs/bpf",
		Cgroup2Path: "/mnt/kmesh_cgroup2",
	}
}

func setDirKernelNative(t *testing.T) options.BpfConfig {
	if err := setDir(); err != nil {
		t.Fatalf("setDir Failed: %v", err)
	}
	return options.BpfConfig{
		Mode:        constants.KernelNativeMode,
		BpfFsPath:   "/sys/fs/bpf",
		Cgroup2Path: "/mnt/kmesh_cgroup2",
	}
}

// Test Kmesh Normal DualEngine
func runTestNormalDualEngine(t *testing.T) {
	config := setDirDualEngine(t)

	NormalStart(t, config)
}

// Test Kmesh Normal KernelNative
func runTestNormalKernelNative(t *testing.T) {
	config := setDirKernelNative(t)

	NormalStart(t, config)
}

func KmeshRestart(t *testing.T, config options.BpfConfig) {
	var versionPath string
	restart.SetStartType(restart.Normal)
	bpfLoader := NewBpfLoader(&config)
	if err := bpfLoader.Start(); err != nil {
		assert.ErrorIsf(t, err, nil, "bpfLoader start failed %v", err)
	}
	assert.Equal(t, restart.Normal, restart.GetStartType(), "set kmesh start status failed")
	restart.SetExitType(restart.Restart)
	bpfLoader.Stop()

	if config.KernelNativeEnabled() {
		versionPath = filepath.Join(config.BpfFsPath + "/bpf_kmesh/map/")
	} else if config.DualEngineEnabled() {
		versionPath = filepath.Join(config.BpfFsPath + "/bpf_kmesh_workload/map/")
	}
	_, err := os.Stat(versionPath)
	assert.ErrorIsf(t, err, nil, "bpfLoader Stop failed, versionPath is not exist: %v", err)

	// Restart
	bpfLoader = NewBpfLoader(&config)
	if err := bpfLoader.Start(); err != nil {
		assert.ErrorIsf(t, err, nil, "bpfLoader start failed %v", err)
	}
	assert.Equal(t, restart.Restart, restart.GetStartType(), "set kmesh start status:Restart failed")
	restart.SetExitType(restart.Normal)
	bpfLoader.Stop()
}

// Test Kmesh Restart DualEngine
func runTestRestartDualEngine(t *testing.T) {
	config := setDirDualEngine(t)
	KmeshRestart(t, config)
}

// Test Kmesh Restart KernelNative
func runTestRestartKernelNative(t *testing.T) {
	config := setDirKernelNative(t)
	KmeshRestart(t, config)
}

func TestGetNodePodSubGateway(t *testing.T) {
	type args struct {
		node *corev1.Node
	}
	tests := []struct {
		name string
		args args
		want [16]byte
	}{
		{
			name: "test Generated nodeIP",
			args: args{
				node: &corev1.Node{
					Spec: corev1.NodeSpec{
						PodCIDR: "10.244.0.0/24",
					},
				},
			},
			want: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 244, 0, 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getNodePodSubGateway(tt.args.node)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_getNodeIPAddress(t *testing.T) {
	type args struct {
		node *corev1.Node
	}
	tests := []struct {
		name string
		args args
		want [16]byte
	}{
		{
			name: "get Node IP address",
			args: args{
				node: &corev1.Node{
					Spec: corev1.NodeSpec{
						PodCIDR: "10.244.0.0/24",
					},
					Status: corev1.NodeStatus{
						Addresses: []corev1.NodeAddress{
							{
								Type:    corev1.NodeInternalIP,
								Address: "172.18.0.3",
							},
						},
					},
				},
			},
			want: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 172, 18, 0, 3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getNodeIPAddress(tt.args.node)
			assert.Equal(t, tt.want, got)
		})
	}
}
