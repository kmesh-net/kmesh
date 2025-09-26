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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"

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

func TestLoadCompileTimeSpecs_KernelNative(t *testing.T) {
	config := setDirKernelNative(t)
	specs, err := restart.LoadCompileTimeSpecs(&config)
	require.NoError(t, err)
	require.Contains(t, specs, "KmeshCgroupSock")
	require.Contains(t, specs, "KmeshCgroupSockCompat")
	require.Contains(t, specs, "KmeshSockops")
	require.Contains(t, specs, "KmeshSockopsCompat")
	require.Contains(t, specs, "KmeshTcMarkEncrypt")
	require.Contains(t, specs, "KmeshTcMarkEncryptCompat")
	require.Contains(t, specs, "KmeshTcMarkDecrypt")
	require.Contains(t, specs, "KmeshTcMarkDecryptCompat")
	for specName, mp := range specs {
		t.Logf("verifying maps for spec %s", specName)
		require.NotEmpty(t, mp, "spec %s has no maps", specName)
		for mapName, spec := range mp {
			require.NotNil(t, spec, "mapSpec %s in %s is nil", mapName, specName)
			require.NotEmpty(t, spec.Name, "MapSpec.Name empty for %s/%s", specName, mapName)
			t.Logf("  Map %-30s Key type: %-30v Value type: %v",
				mapName,
				spec.Key,
				spec.Value,
			)
			if keyStructType, ok := spec.Key.(*btf.Struct); ok {
				t.Logf("    Fields of %s:", keyStructType.Name)
				for _, member := range keyStructType.Members {
					offsetBytes := member.Offset / 8
					t.Logf("      - %-20s Type: %-20s Offset: %3d bytes",
						member.Name,
						member.Type.TypeName(),
						offsetBytes,
					)
				}
			}
			if structType, ok := spec.Value.(*btf.Struct); ok {
				t.Logf("    Fields of %s:", structType.Name)
				for _, member := range structType.Members {
					offsetBytes := member.Offset / 8
					t.Logf("      - %-20s Type: %-20s Offset: %3d bytes",
						member.Name,
						member.Type.TypeName(),
						offsetBytes,
					)
				}
			}
		}
	}
}

func TestLoadCompileTimeSpecs_DualEngine(t *testing.T) {
	config := setDirDualEngine(t)
	specs, err := restart.LoadCompileTimeSpecs(&config)
	require.NoError(t, err)
	require.Contains(t, specs, "KmeshCgroupSockWorkload")
	require.Contains(t, specs, "KmeshCgroupSockWorkloadCompat")
	require.Contains(t, specs, "KmeshSockopsWorkload")
	require.Contains(t, specs, "KmeshSockopsWorkloadCompat")
	require.Contains(t, specs, "KmeshXDPAuth")
	require.Contains(t, specs, "KmeshXDPAuthCompat")
	require.Contains(t, specs, "KmeshSendmsg")
	require.Contains(t, specs, "KmeshSendmsgCompat")
	require.Contains(t, specs, "KmeshCgroupSkb")
	require.Contains(t, specs, "KmeshCgroupSkbCompat")
	require.Contains(t, specs, "KmeshTcMarkEncrypt")
	require.Contains(t, specs, "KmeshTcMarkEncryptCompat")
	require.Contains(t, specs, "KmeshTcMarkDecrypt")
	require.Contains(t, specs, "KmeshTcMarkDecryptCompat")
	for name, mp := range specs {
		t.Logf("verifying maps for spec %s", name)
		require.NotEmpty(t, mp, "spec %s has no maps", name)
		for mname, spec := range mp {
			require.NotNil(t, spec, "mapSpec %s in %s is nil", mname, name)
			require.NotEmpty(t, spec.Name, "MapSpec.Name empty for %s/%s", name, mname)
		}
	}
}

// helper: build a simple btf.Int without relying on encoding constants
func intType(name string, sizeBytes int) *btf.Int {
	return &btf.Int{
		Name: name,
		Size: uint32(sizeBytes * 8),
	}
}

// Test diffStructInfoAgainstBTF basic cases: Added / Removed / Offset / Nested
func TestDiffStructInfoAgainstBTF_Basics(t *testing.T) {
	// old StructInfo: one member "a"
	old := restart.StructInfo{
		Name: "S_old",
		Members: []restart.MemberInfo{
			{
				Name:         "a",
				TypeName:     "uint32",
				Offset:       0, // we'll match against btf.Member.Offset below (no /8 used in current diff impl)
				BitfieldSize: 0,
			},
		},
	}

	// New BTF struct: has "a" and new field "b" => Added == true
	newWithAdded := &btf.Struct{
		Name: "S_new_added",
		Members: []btf.Member{
			{
				Name:         "a",
				Type:         intType("uint32", 4),
				Offset:       btf.Bits(0),
				BitfieldSize: btf.Bits(32),
			},
			{
				Name:         "b",
				Type:         intType("uint8", 1),
				Offset:       btf.Bits(32),
				BitfieldSize: btf.Bits(0),
			},
		},
	}

	d := restart.DiffStructInfoAgainstBTF(old, newWithAdded, make(map[string]bool))
	if !d.Added {
		t.Fatalf("expected Added==true, got %+v", d)
	}

	// New BTF struct: missing "a" => Removed true
	newRemoved := &btf.Struct{
		Name: "S_new_removed",
		Members: []btf.Member{
			{
				Name:         "x",
				Type:         intType("uint32", 4),
				Offset:       btf.Bits(0),
				BitfieldSize: btf.Bits(0),
			},
		},
	}
	d = restart.DiffStructInfoAgainstBTF(old, newRemoved, make(map[string]bool))
	if !d.Removed {
		t.Fatalf("expected Removed==true, got %+v", d)
	}

	// Offset change: new has "a" but with different Offset
	newOff := &btf.Struct{
		Name: "S_new_off",
		Members: []btf.Member{
			{
				Name:         "a",
				Type:         intType("uint32", 4),
				Offset:       btf.Bits(8), // note: current diff code compares uint32(member.Offset) vs saved Offset
				BitfieldSize: btf.Bits(0),
			},
		},
	}
	// To make the offset comparison hit, set old.Members[0].Offset to uint32(member.Offset)
	oldOffsetMatch := old
	oldOffsetMatch.Members[0].Offset = uint32(newOff.Members[0].Offset) // direct match -> no offset diff
	d = restart.DiffStructInfoAgainstBTF(oldOffsetMatch, newOff, make(map[string]bool))
	if d.OffsetChanged {
		t.Fatalf("did not expect OffsetChanged when offsets match (got %+v)", d)
	}
	// Now set old offset to different value -> expect OffsetChanged
	oldOffsetMismatch := old
	oldOffsetMismatch.Members[0].Offset = uint32(0)
	d = restart.DiffStructInfoAgainstBTF(oldOffsetMismatch, newOff, make(map[string]bool))
	if !d.OffsetChanged {
		t.Fatalf("expected OffsetChanged true, got %+v", d)
	}
}

func TestDiffStructInfoAgainstBTF_NestedIncompatible(t *testing.T) {
	// old: inner { a: uint32 }, outer { x: inner, y: uint64 }
	innerInt := intType("uint32", 4)
	oldInner := &btf.Struct{
		Name: "inner",
		Members: []btf.Member{
			{
				Name:         "a",
				Type:         innerInt,
				Offset:       btf.Bits(0),
				BitfieldSize: btf.Bits(0),
			},
		},
	}
	outerUint := intType("__u64", 8)
	oldOuter := &btf.Struct{
		Name: "outer",
		Members: []btf.Member{
			{
				Name:         "x",
				Type:         oldInner,
				Offset:       btf.Bits(0),
				BitfieldSize: btf.Bits(0),
			},
			{
				Name:         "y",
				Type:         outerUint,
				Offset:       btf.Bits(32),
				BitfieldSize: btf.Bits(0),
			},
		},
	}

	// persisted registry stores old definitions (StructInfo with Nested expanded)
	registry := map[string]restart.StructInfo{
		"inner": {
			Name: "inner",
			Members: []restart.MemberInfo{
				{
					Name:         "a",
					TypeName:     "uint32",
					Offset:       uint32(oldInner.Members[0].Offset), // use raw bit value as in your diff impl
					BitfieldSize: 0,
				},
			},
		},
		"outer": {
			Name: "outer",
			Members: []restart.MemberInfo{
				{
					Name:         "x",
					TypeName:     "inner",
					Offset:       uint32(oldOuter.Members[0].Offset),
					BitfieldSize: 0,
					Nested: &restart.StructInfo{
						Name: "inner",
						Members: []restart.MemberInfo{
							{Name: "a", TypeName: "uint32", Offset: uint32(oldInner.Members[0].Offset), BitfieldSize: 0},
						},
					},
				},
				{
					Name:         "y",
					TypeName:     "__u64",
					Offset:       uint32(oldOuter.Members[1].Offset),
					BitfieldSize: 0,
				},
			},
		},
	}

	// new: inner_changed { b: uint32 }  <-- note: field name changed (a -> b)
	newInnerChanged := &btf.Struct{
		Name: "inner_changed",
		Members: []btf.Member{
			{
				Name:         "b", // different name -> incompatible
				Type:         intType("uint32", 4),
				Offset:       btf.Bits(0),
				BitfieldSize: btf.Bits(0),
			},
		},
	}
	// new outer uses this new inner_changed type
	newOuter := &btf.Struct{
		Name: "outer",
		Members: []btf.Member{
			{
				Name:         "x",
				Type:         newInnerChanged,
				Offset:       btf.Bits(0),
				BitfieldSize: btf.Bits(0),
			},
			{
				Name:         "y",
				Type:         outerUint,
				Offset:       btf.Bits(32),
				BitfieldSize: btf.Bits(0),
			},
		},
	}

	// Compare persisted outer (StructInfo) against newOuter (btf.Struct).
	diff := restart.DiffStructInfoAgainstBTF(registry["outer"], newOuter, make(map[string]bool))

	// Expect nested change (because inner's member name changed a->b)
	if !diff.NestedChanged && !diff.TypeChanged && !diff.Removed && !diff.Added {
		t.Fatalf("expected incompatibility detected (NestedChanged/TypeChanged/Added/Removed), got %#v", diff)
	}
}

// Test nested struct comparisons and compatibility path in migrateMap
func TestDiffStructInfoAgainstBTF_NestedAndMigrateMap_Compatible(t *testing.T) {
	// Build nested btf structs: inner { a:uint32 }, outer { x:inner, y:uint64 }
	innerInt := intType("uint32", 4)
	inner := &btf.Struct{
		Name: "inner",
		Members: []btf.Member{
			{
				Name:         "a",
				Type:         innerInt,
				Offset:       btf.Bits(0),
				BitfieldSize: btf.Bits(0),
			},
		},
	}
	outerUint := intType("__u64", 8)
	outer := &btf.Struct{
		Name: "outer",
		Members: []btf.Member{
			{
				Name:         "x",
				Type:         inner,
				Offset:       btf.Bits(0),
				BitfieldSize: btf.Bits(0),
			},
			{
				Name:         "y",
				Type:         outerUint,
				Offset:       btf.Bits(32),
				BitfieldSize: btf.Bits(0),
			},
		},
	}

	// persisted StructInfo registry: includes both inner and outer
	registry := map[string]restart.StructInfo{
		"inner": {
			Name: "inner",
			Members: []restart.MemberInfo{
				{Name: "a", TypeName: "uint32", Offset: uint32(inner.Members[0].Offset), BitfieldSize: 0},
			},
		},
		"outer": {
			Name: "outer",
			Members: []restart.MemberInfo{
				{Name: "x", TypeName: "inner", Offset: uint32(outer.Members[0].Offset), BitfieldSize: 0, Nested: &restart.StructInfo{
					Name: "inner",
					Members: []restart.MemberInfo{
						{Name: "a", TypeName: "uint32", Offset: uint32(inner.Members[0].Offset), BitfieldSize: 0},
					},
				}},
				{Name: "y", TypeName: "__u64", Offset: uint32(outer.Members[1].Offset), BitfieldSize: 0},
			},
		},
	}

	// persisted map spec using outer
	oldMapSpec := restart.PersistedMapSpec{
		Name:       "km_nested_map",
		Type:       ebpf.Hash.String(),
		KeySize:    4,
		ValueSize:  16,
		MaxEntries: 128,
		KeyInfo:    restart.StructInfo{Name: "int", Members: nil},
		ValueInfo:  registry["outer"],
	}

	// new compiled MapSpec that uses the same outer struct
	newMapSpec := &ebpf.MapSpec{
		Name:       "km_nested_map",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  16,
		MaxEntries: 128,
		Key:        intType("int", 4), // key type non-struct in this test
		Value:      outer,
	}

	// Call migrateMap: because the persisted value layout matches newMapSpec.Value,
	// migrateMap should consider them compatible and return (nil, nil) (no creation).
	m, err := restart.MigrateMap(&oldMapSpec, newMapSpec, "pkg", "mapNested", filepath.Join(t.TempDir(), "mapping"))
	if err != nil {
		t.Fatalf("migrateMap returned unexpected error: %v", err)
	}
	if m != nil {
		t.Fatalf("expected nil map (reuse existing), got non-nil: %v", m)
	}
}
