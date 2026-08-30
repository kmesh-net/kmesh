//go:build linux && (amd64 || arm64) && !aix && !ppc64

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

package bpftests

import (
	"encoding/binary"
	"errors"
	"net"
	"path"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"kmesh.net/kmesh/pkg/bpf/factory"
	"kmesh.net/kmesh/pkg/constants"
)

func load_bpf_prog_to_cgroup_ads(t *testing.T, objFilePath string, progName string, cgroupPath string) (*ebpf.Collection, link.Link) {
	spec := loadAndPrepSpec(t, path.Join(*testPath, objFilePath))
	
	// Remove ADS tail-call programs so the verifier doesn't try to load them as independent programs and fail due to unrolled loop complexities
	delete(spec.Programs, "cluster_manager")
	delete(spec.Programs, "filter_manager")
	delete(spec.Programs, "filter_chain_manager")
	delete(spec.Programs, "route_config_manager")

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier error: %+v", ve)
		} else {
			t.Fatal("loading collection:", err)
		}
	}
	progSpec, ok := spec.Programs[progName]
	if !ok {
		coll.Close()
		t.Fatalf("Program %s not found in spec", progName)
	}
	prog := coll.Programs[progName]
	if prog == nil {
		coll.Close()
		t.Fatalf("Program %s not found in collection", progName)
	}
	lk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  progSpec.AttachType,
		Program: prog,
	})
	if err != nil {
		coll.Close()
		t.Fatalf("Failed to attach cgroup: %v", err)
	}
	return coll, lk
}

func load_bpf_2_cgroup_ads(t *testing.T, objFilePath string, cgroupPath string) (*ebpf.Collection, link.Link) {
	spec := loadAndPrepSpec(t, path.Join(*testPath, objFilePath))

	delete(spec.Programs, "cluster_manager")
	delete(spec.Programs, "filter_manager")
	delete(spec.Programs, "filter_chain_manager")
	delete(spec.Programs, "route_config_manager")

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier error: %+v", ve)
		} else {
			t.Fatal("loading collection:", err)
		}
	}

	prog := coll.Programs["sockops_prog"]
	if prog == nil {
		coll.Close()
		t.Fatal("No SockOps program found in collection")
	}

	lk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: prog,
	})
	if err != nil {
		coll.Close()
		t.Fatalf("Failed to attach cgroup: %v", err)
	}
	return coll, lk
}

func testAds(t *testing.T) {
	t.Run("CgroupSock", testAdsCgroupSock)
	t.Run("SockOps", testAdsSockOps)
}

func testAdsCgroupSock(t *testing.T) {
	tests := []unitTests_BUILD_CONTEXT{
		{
			objFilename: "ads_cgroup_sock_test.o",
			uts: []unitTest_BUILD_CONTEXT{
				{
					name: "BPF_CGROUP_SOCK_CONNECT4_handle_kmesh_manage_process",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						coll, lk := load_bpf_prog_to_cgroup_ads(t, objFilePath, "cgroup_connect4_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)
						
						enableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperEnableControl))
						if conn, err := net.DialTimeout("tcp4", enableAddr, 2*time.Second); err == nil {
							conn.Close()
						}
						
						kmManageMap := coll.Maps["km_manage"]
						if kmManageMap == nil {
							t.Fatal("Failed to get km_manage map from collection")
						}
						
						iter := kmManageMap.Iterate()
						count := 0
						var key [16]byte
						var value uint32
						for iter.Next(&key, &value) {
							count++
						}
						if err := iter.Err(); err != nil {
							t.Fatalf("Iterate error: %v", err)
						}
						if count != 1 {
							t.Fatalf("Expected 1 entry in km_manage map, but got %d", count)
						}
						
						disableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperDisableControl))
						if conn, err := net.DialTimeout("tcp4", disableAddr, 2*time.Second); err == nil {
							conn.Close()
						}
						
						iter = kmManageMap.Iterate()
						count = 0
						for iter.Next(&key, &value) {
							count++
						}
						if count != 0 {
							t.Fatalf("Expected 0 entry in km_manage map, but got %d", count)
						}
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.objFilename, tt.run())
	}
}

func testAdsSockOps(t *testing.T) {
	tests := []unitTests_BUILD_CONTEXT{
		{
			objFilename: "ads_sockops_test.o",
			uts: []unitTest_BUILD_CONTEXT{
				{
					name: "BPF_SOCK_OPS_TCP_CONNECT_CB__modify_kmesh_managed_ip",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)

						coll, lk := load_bpf_2_cgroup_ads(t, objFilePath, cgroupPath)
						defer coll.Close()
						defer lk.Close()

						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						enableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperEnableControl))
						if conn, err := net.DialTimeout("tcp4", enableAddr, 2*time.Second); err == nil {
							conn.Close()
						}

						kmManageMap := coll.Maps["km_manage"]
						if kmManageMap == nil {
							t.Fatal("Failed to get km_manage map from collection")
						}

						var (
							keyBytes [16]byte
							value    uint32
							count    uint32
						)

						iter := kmManageMap.Iterate()
						for iter.Next(&keyBytes, &value) {
							ip4HostOrder := binary.LittleEndian.Uint32(keyBytes[0:4])
							ipStr := net.IPv4(
								byte(ip4HostOrder),
								byte(ip4HostOrder>>8),
								byte(ip4HostOrder>>16),
								byte(ip4HostOrder>>24)).String()
							t.Logf("km_manage[%s] = %d", ipStr, value)
							count++
						}

						if err := iter.Err(); err != nil {
							t.Fatalf("Map iteration failed: %v", err)
						}

						if count != 1 {
							t.Fatalf("Expected 1 entry in km_manage map, but got %d", count)
						}

						disableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperDisableControl))
						if conn, err := net.DialTimeout("tcp4", disableAddr, 2*time.Second); err == nil {
							conn.Close()
						}

						iter = kmManageMap.Iterate()
						count = 0
						for iter.Next(&keyBytes, &value) {
							count++
						}

						if count != 0 {
							t.Fatalf("Expected 0 entry in km_manage map, but got %d", count)
						}
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.objFilename, tt.run())
	}
}
