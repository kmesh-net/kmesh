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
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"path"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"kmesh.net/kmesh/api/v2/workloadapi/security"
	bpf2go "kmesh.net/kmesh/bpf/kmesh/bpf2go/dualengine"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/factory"
	bpfUtils "kmesh.net/kmesh/pkg/bpf/utils"
	bpfWorkload "kmesh.net/kmesh/pkg/bpf/workload"
	"kmesh.net/kmesh/pkg/cache/v2/maps"
	"kmesh.net/kmesh/pkg/constants"
	controllerWorkload "kmesh.net/kmesh/pkg/controller/workload"
	"kmesh.net/kmesh/pkg/controller/workload/bpfcache"
)

func testWorkload(t *testing.T) {
	t.Run("XDP", testXDP)
	t.Run("SockOps", testSockOps)
}

func testXDP(t *testing.T) {
	XDPtests := []unitTests_BPF_PROG_TEST_RUN{
		{
			objFilename: "xdp_shutdown_in_userspace_test.o",
			uts: []unitTest_BPF_PROG_TEST_RUN{
				{
					name: "1_shutdown_in_userspace__should_shutdown",
					setupInUserSpace: func(t *testing.T, coll *ebpf.Collection) {
						workload_xdp_registerTailCall(t, coll)
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
					},
				},
				{
					name: "2_shutdown_in_userspace__should_not_shutdown",
					setupInUserSpace: func(t *testing.T, coll *ebpf.Collection) {
						workload_xdp_registerTailCall(t, coll)
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
					},
				},
			},
		},
		{
			objFilename: "xdp_authz_offload_test.o",
			uts: []unitTest_BPF_PROG_TEST_RUN{
				{
					name: "3_deny_policy_matched",
					setupInUserSpace: func(t *testing.T, coll *ebpf.Collection) {
						// xdp_authz(struct xdp_md *ctx) -tail call->
						// policies_check(struct xdp_md *ctx) -tail call->
						// policy_check(struct xdp_md *ctx)
						//   if(matched)
						//     return match_ctx->action == ISTIO__SECURITY__ACTION__DENY ? XDP_DROP : XDP_PASS;

						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.ENABLED,
						})

						workload_xdp_registerTailCall(t, coll)
						workload_setMapsEnv(t, coll)
						if workload, err := bpfWorkload.NewBpfWorkload(&options.BpfConfig{
							Mode:        constants.DualEngineMode,
							BpfFsPath:   constants.BpfFsPath,
							Cgroup2Path: constants.Cgroup2Path,
						}); err != nil {
							t.Fatalf("NewBpfWorkload failed: %v", err)
						} else {
							if err := workload.DeserialInit(); err != nil {
								t.Fatalf("DeserialInit failed: %v", err)
							}
						}
						workloadProcessor := controllerWorkload.NewProcessor(bpf2go.KmeshCgroupSockWorkloadMaps{
							KmWlpolicy: coll.Maps["km_wlpolicy"],
							KmFrontend: coll.Maps["km_frontend"],
						})

						workloadbpf := workloadProcessor.GetBpfCache()
						if err := workloadbpf.FrontendUpdate(&bpfcache.FrontendKey{
							Ip: [16]byte{10, 1, 0, 15},
						}, &bpfcache.FrontendValue{
							UpstreamId: 0x01,
						}); err != nil {
							t.Fatalf("FrontendUpdate failed: %v", err)
						}
						if err := workloadbpf.WorkloadPolicyUpdate(&bpfcache.WorkloadPolicyKey{
							WorklodId: 0x01,
						}, &bpfcache.WorkloadPolicyValue{
							PolicyIds: [4]uint32{1},
						}); err != nil {
							t.Fatalf("WorkloadPolicyUpdate failed: %v", err)
						}

						// set policy
						policy_k := uint32(1)
						denyPolicy := &security.Authorization{
							Name:   "bpfut_deny__10.0.0.15->10.1.0.15:80",
							Action: security.Action_DENY,
							Rules: []*security.Rule{
								{
									Clauses: []*security.Clause{
										{
											Matches: []*security.Match{
												{
													SourceIps: []*security.Address{
														{
															Address: []byte{10, 0, 0, 15},
															Length:  32,
														},
													},
													DestinationIps: []*security.Address{
														{
															Address: []byte{10, 1, 0, 15},
															Length:  32,
														},
													},
													DestinationPorts: []uint32{80},
												},
											},
										},
									},
								},
							},
						}
						if err := maps.AuthorizationUpdate(policy_k, denyPolicy); err != nil {
							t.Fatalf("AuthorizationUpdate failed: %v", err)
						}
					},
				},
				{
					name: "4_allow_policy_matched",
					setupInUserSpace: func(t *testing.T, coll *ebpf.Collection) {
						// xdp_authz(struct xdp_md *ctx) -tail call->
						// policies_check(struct xdp_md *ctx) -tail call->
						// policy_check(struct xdp_md *ctx)
						//   if(matched)
						//     return match_ctx->action == ISTIO__SECURITY__ACTION__DENY ? XDP_DROP : XDP_PASS;

						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.ENABLED,
						})

						workload_xdp_registerTailCall(t, coll)
						workload_setMapsEnv(t, coll)
						if workload, err := bpfWorkload.NewBpfWorkload(&options.BpfConfig{
							Mode:        constants.DualEngineMode,
							BpfFsPath:   constants.BpfFsPath,
							Cgroup2Path: constants.Cgroup2Path,
						}); err != nil {
							t.Fatalf("NewBpfWorkload failed: %v", err)
						} else {
							if err := workload.DeserialInit(); err != nil {
								t.Fatalf("DeserialInit failed: %v", err)
							}
						}
						bpfmaps := bpf2go.KmeshCgroupSockWorkloadMaps{
							KmWlpolicy: coll.Maps["km_wlpolicy"],
							KmFrontend: coll.Maps["km_frontend"],
						}
						workloadProcessor := controllerWorkload.NewProcessor(bpfmaps)

						workloadbpf := workloadProcessor.GetBpfCache()
						if err := workloadbpf.FrontendUpdate(&bpfcache.FrontendKey{
							Ip: [16]byte{10, 1, 0, 15},
						}, &bpfcache.FrontendValue{
							UpstreamId: 0x01,
						}); err != nil {
							t.Fatalf("FrontendUpdate failed: %v", err)
						}
						if err := workloadbpf.WorkloadPolicyUpdate(&bpfcache.WorkloadPolicyKey{
							WorklodId: 0x01,
						}, &bpfcache.WorkloadPolicyValue{
							PolicyIds: [4]uint32{0},
						}); err != nil {
							t.Fatalf("WorkloadPolicyUpdate failed: %v", err)
						}

						policy_k := uint32(0)
						allowPolicy := &security.Authorization{
							Name:   "bpfut_allow__10.0.0.15->10.1.0.15:80",
							Action: security.Action_ALLOW,
							Rules: []*security.Rule{
								{
									Clauses: []*security.Clause{
										{
											Matches: []*security.Match{
												{
													SourceIps: []*security.Address{
														{
															Address: []byte{10, 0, 0, 15},
															Length:  32,
														},
													},
													DestinationIps: []*security.Address{
														{
															Address: []byte{10, 1, 0, 15},
															Length:  32,
														},
													},
													DestinationPorts: []uint32{80},
												},
											},
										},
									},
								},
							},
						}
						if err := maps.AuthorizationUpdate(policy_k, allowPolicy); err != nil {
							t.Fatalf("AuthorizationUpdate failed: %v", err)
						}
					},
				},
			},
		},
	}

	for _, tt := range XDPtests {
		t.Run(tt.objFilename, tt.run())
	}
}

// workload_xdp_registerTailCall registers the tail call for XDP programs.
func workload_xdp_registerTailCall(t *testing.T, coll *ebpf.Collection) {
	if coll == nil {
		t.Fatal("coll is nil")
	}
	registerTailCall(t, coll, constants.XDPTailCallMap, constants.TailCallPoliciesCheck, "policies_check")
	registerTailCall(t, coll, constants.XDPTailCallMap, constants.TailCallPolicyCheck, "policy_check")
	registerTailCall(t, coll, constants.XDPTailCallMap, constants.TailCallAuthInUserSpace, "xdp_shutdown_in_userspace")
}

// workload_setMapsEnv prepares the BPF testing environment by configuring a BPF workload
// and setting up environment variables for various BPF maps.
func workload_setMapsEnv(t *testing.T, coll *ebpf.Collection) {
	if coll == nil {
		t.Fatal("coll is nil")
	}

	if err := bpfUtils.SetEnvByBpfMapId(coll.Maps["km_authz_policy"], "Authorization"); err != nil {
		t.Fatalf("SetEnvByBpfMapId failed: %v", err)
	}
	if err := bpfUtils.SetEnvByBpfMapId(coll.Maps["kmesh_map64"], "KmeshMap64"); err != nil {
		t.Fatalf("SetEnvByBpfMapId failed: %v", err)
	}
	if err := bpfUtils.SetEnvByBpfMapId(coll.Maps["kmesh_map192"], "KmeshMap192"); err != nil {
		t.Fatalf("SetEnvByBpfMapId failed: %v", err)
	}
	if err := bpfUtils.SetEnvByBpfMapId(coll.Maps["kmesh_map296"], "KmeshMap296"); err != nil {
		t.Fatalf("SetEnvByBpfMapId failed: %v", err)
	}
	if err := bpfUtils.SetEnvByBpfMapId(coll.Maps["kmesh_map1600"], "KmeshMap1600"); err != nil {
		t.Fatalf("SetEnvByBpfMapId failed: %v", err)
	}
}

func testSockOps(t *testing.T) {
	tests := []unitTests_BUILD_CONTEXT{
		{
			objFilename: "workload_sockops.o",
			uts: []unitTest_BUILD_CONTEXT{
				{
					name: "BPF_SOCK_OPS_TCP_CONNECT_CB",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)

						// load the eBPF program
						coll, lk := load_bpf_2_cgroup(t, objFilePath, cgroupPath)
						defer coll.Close()
						defer lk.Close()

						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_ip
						enableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperEnableControl))
						net.DialTimeout("tcp", enableAddr, 2*time.Second)

						// Execute bpftool map dump and log the results (optional, for debugging)
						// cmd := exec.Command("bpftool", "map", "dump", "name", "km_manage")
						// output, err := cmd.CombinedOutput()
						// if err != nil {
						// 	t.Logf("Failed to execute bpftool command: %v", err)
						// } else {
						// 	// Log the raw output from bpftool for comparison
						// 	t.Logf("bpftool map dump name km_manage output:\n%s", string(output))
						// }

						// Get the km_manage map from the collection
						kmManageMap := coll.Maps["km_manage"]
						if kmManageMap == nil {
							t.Fatal("Failed to get km_manage map from collection")
						}

						var (
							keyBytes [16]byte // sizeof(struct manager_key)
							value    uint32
							count    uint32
							iter     *ebpf.MapIterator
						)

						iter = kmManageMap.Iterate()
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

						// remove_kmesh_managed_ip
						disableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperDisableControl))
						net.DialTimeout("tcp", disableAddr, 2*time.Second)

						iter = kmManageMap.Iterate()
						count = 0
						for iter.Next(&keyBytes, &value) {
							count++
						}

						if err := iter.Err(); err != nil {
							t.Fatalf("Map iteration failed: %v", err)
						}

						if count != 0 {
							t.Fatalf("Expected 0 entry in km_manage map, but got %d", count)
						}
					},
				},
				{
					name: "BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB_auth_ip_tuple",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						localIP := get_local_ipv4(t)
						serverPort := 54321
						serverSocket := localIP + ":" + strconv.Itoa(serverPort)

						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)

						// load the eBPF program
						coll, lk := load_bpf_2_cgroup(t, objFilePath, cgroupPath)
						defer coll.Close()
						defer lk.Close()

						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_ip
						enableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperEnableControl))
						(&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP: net.ParseIP(localIP),
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp4", enableAddr)

						// Create a TCP server listener
						listener, err := net.Listen("tcp", serverSocket)
						if err != nil {
							t.Fatalf("Failed to start TCP server: %v", err)
						}
						defer listener.Close()

						// try to connect to the server
						conn, err := net.DialTimeout("tcp4", serverSocket, 2*time.Second)
						if err != nil {
							t.Fatalf("Failed to connect to server: %v", err)
						}
						defer conn.Close()

						// Now, the TCP connection between localAddr and serverSocket has been established
						time.Sleep(1 * time.Second)

						// Check the contents of ringbuf km_auth_req
						kmAuthReqMap := coll.Maps["km_auth_req"]
						if kmAuthReqMap == nil {
							t.Fatal("Failed to get km_auth_req map from collection")
						}
						rd, err := ringbuf.NewReader(kmAuthReqMap)
						if err != nil {
							t.Fatalf("Failed to create ringbuf reader: %v", err)
						}
						defer rd.Close()

						var event [40]byte // sizeof(struct ringbuf_msg_type)
						record, err := rd.Read()
						if err != nil {
							t.Fatalf("Failed to read from ringbuf: %v", err)
						}
						if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
							log.Printf("parsing ringbuf event: %s", err)
						}
						protoType := binary.LittleEndian.Uint32(event[0:4])
						srcIP := net.IPv4(event[4], event[5], event[6], event[7])
						dstIP := net.IPv4(event[8], event[9], event[10], event[11])
						srcPort := binary.BigEndian.Uint16(event[12:14])
						dstPort := binary.BigEndian.Uint16(event[14:16])
						t.Logf("Received ringbuf_msg: type=%d, src=%s:%d, dst=%s:%d", protoType, srcIP, srcPort, dstIP, dstPort)

						// Check
						if protoType != 0 /*IPV4*/ || dstIP.String() != localIP || int(dstPort) != serverPort {
							t.Fatalf("Expected dst IP and port to be %s:%d, but got %s:%d", localIP, serverPort, dstIP, dstPort)
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

func mount_cgroup2(t *testing.T, cgroupPath string) {
	var err error

	// mount cgroup2
	if err = os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Logf("Failed to create cgroup directory %s (might already exist): %v", cgroupPath, err)
	}
	err = syscall.Mount("none", cgroupPath, "cgroup2", 0, "")
	if err != nil {
		errno, ok := err.(syscall.Errno)
		if ok && errno == syscall.EBUSY {
			t.Logf("Cgroup v2 already mounted at %s", cgroupPath)
		} else {
			t.Fatalf("Failed to mount cgroup2 at %s: %v. Ensure test is run with sudo.", cgroupPath, err)
		}
	}
}

func load_bpf_2_cgroup(t *testing.T, objFilename string, cgroupPath string) (*ebpf.Collection, link.Link) {
	if cgroupPath == "" {
		t.Fatal("cgroupPath is empty")
	}
	if objFilename == "" {
		t.Fatal("objFilename is empty")
	}

	// load the eBPF program
	spec := loadAndPrepSpec(t, path.Join(*testPath, objFilename))
	var (
		coll *ebpf.Collection
		err  error
	)

	// Load the eBPF collection into the kernel
	coll, err = ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier error: %+v", ve)
		} else {
			t.Fatal("loading collection:", err)
		}
	}

	lk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    constants.Cgroup2Path,
		Attach:  spec.Programs["sockops_prog"].AttachType,
		Program: coll.Programs["sockops_prog"],
	})
	if err != nil {
		coll.Close()
		t.Fatalf("Failed to attach cgroup: %v", err)
	}
	return coll, lk
}

func get_local_ipv4(t *testing.T) string {
	testConn, testErr := net.Dial("tcp4", "8.8.8.8:53")
	if testErr != nil {
		t.Fatalf("Failed to create test connection: %v", testErr)
	}
	defer testConn.Close()

	localAddr, _, err := net.SplitHostPort(testConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Failed to extract host from address: %v", err)
	}
	return localAddr
}
