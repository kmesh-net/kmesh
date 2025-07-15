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
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"kmesh.net/kmesh/api/v2/workloadapi/security"
	bpf2go "kmesh.net/kmesh/bpf/kmesh/bpf2go/dualengine"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/auth"
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
			objFilename: "workload_sockops_test.o",
			uts: []unitTest_BUILD_CONTEXT{
				{
					name: "BPF_SOCK_OPS_TCP_CONNECT_CB__modify_kmesh_managed_ip",
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
						net.DialTimeout("tcp4", enableAddr, 2*time.Second)

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
						net.DialTimeout("tcp4", disableAddr, 2*time.Second)

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
					name: "BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB__enable_encoding_metadata",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						localIP := get_local_ipv4(t)
						clientPort := 12345
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
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp4", enableAddr)

						// Create a TCP server listener
						listener, err := net.Listen("tcp4", serverSocket)
						if err != nil {
							t.Fatalf("Failed to start TCP server: %v", err)
						}
						defer listener.Close()

						// try to connect to the server using the specified client port
						conn, err := (&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp4", serverSocket)
						if err != nil {
							t.Fatalf("Failed to connect to server: %v", err)
						} else {
							t.Logf("Connect success: %s:%d -> %s:%d", localIP, clientPort, localIP, serverPort)
						}
						defer conn.Close()

						// Now, the TCP connection between localIP:12345(client) and localIP:54321(server) has been established
						time.Sleep(1 * time.Second)

						// Get the km_socket map from the collection
						kmSocketMap, ok := coll.Maps["km_socket"]
						if !ok {
							t.Fatal("Failed to get km_socket map from collection")
						}
						var (
							key   [36]byte // sizeof(struct bpf_sock_tuple)
							value uint32
						)
						binary.BigEndian.PutUint32(key[0:4], binary.BigEndian.Uint32(net.ParseIP(localIP).To4())) // __be32 saddr;
						binary.BigEndian.PutUint32(key[4:8], binary.BigEndian.Uint32(net.ParseIP(localIP).To4())) // __be32 daddr;
						binary.BigEndian.PutUint16(key[8:10], uint16(clientPort))                                 // __be16 sport;
						binary.BigEndian.PutUint16(key[10:12], uint16(serverPort))                                // __be16 dport;

						err = kmSocketMap.Lookup(key, &value)
						if err != nil && !strings.Contains(err.Error(), "no space left on device") {
							t.Fatalf("Failed to lookup km_socket map: %v", err)
						}
						t.Logf("km_socket get key[%s:%d->%s:%d], test success.", localIP, clientPort, localIP, serverPort)
					},
				},
				{
					name: "BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB__auth_ip_tuple",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						localIP := get_local_ipv4(t)
						clientPort := 12345
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
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp4", enableAddr)

						// Create a TCP server listener
						listener, err := net.Listen("tcp4", serverSocket)
						if err != nil {
							t.Fatalf("Failed to start TCP server: %v", err)
						}
						defer listener.Close()

						// try to connect to the server using the specified client port
						conn, err := (&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp4", serverSocket)
						if err != nil {
							t.Fatalf("Failed to connect to server: %v", err)
						} else {
							t.Logf("Connect success: %s:%d -> %s:%d", localIP, clientPort, localIP, serverPort)
						}
						defer conn.Close()

						// Now, the TCP connection between localIP:12345(client) and localIP:54321(server) has been established
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
						t.Logf("Received km_auth_req ringbuf_msg: type=%d, src=%s:%d, dst=%s:%d", protoType, srcIP, srcPort, dstIP, dstPort)

						// Check
						if protoType != constants.MSG_TYPE_IPV4 ||
							srcIP.String() != localIP || int(srcPort) != clientPort ||
							dstIP.String() != localIP || int(dstPort) != serverPort {
							t.Fatalf("Expected {protoType: %d, srcIP: %s, srcPort: %d, dstIP: %s, dstPort: %d}, but got {protoType: %d, srcIP: %s, srcPort: %d, dstIP: %s, dstPort: %d}",
								constants.MSG_TYPE_IPV4, localIP, clientPort, localIP, serverPort,
								protoType, srcIP, srcPort, dstIP, dstPort)
						}
					},
				},
				{
					name: "BPF_SOCK_OPS_STATE_CB__clean_auth_map",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						localIP := get_local_ipv4(t)
						clientPort := 12345
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

						// update km_auth_res map
						mapOfAuth, ok := coll.Maps["km_auth_res"]
						if !ok {
							t.Fatal("Failed to get km_auth_res map from collection")
						}
						key := make([]byte, auth.TUPLE_LEN)                                                       // struct ipv4
						binary.BigEndian.PutUint32(key[0:4], binary.BigEndian.Uint32(net.ParseIP(localIP).To4())) // __be32 saddr;
						binary.BigEndian.PutUint32(key[4:8], binary.BigEndian.Uint32(net.ParseIP(localIP).To4())) // __be32 daddr;
						binary.BigEndian.PutUint16(key[8:10], uint16(serverPort))                                 // __be16 sport;
						binary.BigEndian.PutUint16(key[10:12], uint16(clientPort))                                // __be16 dport;
						for i := auth.IPV4_TUPLE_LENGTH; i < len(key); i++ {
							key[i] = 0
						}
						if err := mapOfAuth.Update(key, uint32(1), ebpf.UpdateAny); err != nil {
							t.Fatalf("Failed to update km_auth_res map: %v", err)
						}

						// record_kmesh_managed_ip
						enableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperEnableControl))
						(&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp4", enableAddr)

						// Create a TCP server listener
						listener, err := net.Listen("tcp4", serverSocket)
						if err != nil {
							t.Fatalf("Failed to start TCP server: %v", err)
						}
						defer listener.Close()

						// try to connect to the server using the specified client port
						conn, err := (&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp4", serverSocket)
						if err != nil {
							t.Fatalf("Failed to connect to server: %v", err)
						} else {
							t.Logf("Connect success: %s:%d -> %s:%d", localIP, clientPort, localIP, serverPort)
						}
						conn.Close()

						// Now, the TCP connection between between localIP:12345(client) and localIP:54321(server) has been established and closed
						time.Sleep(1 * time.Second)

						// Check if the entry was deleted from km_auth_res map
						// The same key we inserted earlier should no longer exist in the map
						var value uint32
						err = mapOfAuth.Lookup(key, &value)
						if err == nil {
							t.Fatalf("km_auth_res map entry was not deleted as expected")
						} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
							t.Fatalf("Unexpected error when looking up km_auth_res map: %v", err)
						} else {
							t.Logf("km_auth_res map entry was successfully cleaned up")
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

// mount_cgroup2 mounts a cgroup v2 filesystem at the specified path.
// It creates the directory at cgroupPath if it doesn't exist, then attempts
// to mount a cgroup2 filesystem at that location.
//
// If the cgroup is already mounted (EBUSY error), it logs a message and continues.
// For other mount failures, it fails the test with an error message.
//
// This function requires root privileges to succeed, as mounting filesystems
// is a privileged operation.
//
// Parameters:
//   - t: Testing context for logging and failure reporting
//   - cgroupPath: Directory path where cgroup2 should be mounted
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

// load_bpf_2_cgroup loads an eBPF program from a specified object file and attaches it to the given cgroup path.
// The function loads the eBPF collection into the kernel and specifically attaches the "sockops_prog" program
// from the collection to the cgroup.
//
// Parameters:
//   - t: Testing context for reporting failures
//   - objFilename: Name of the eBPF object file to load (must not be empty)
//   - cgroupPath: Path to the cgroup where the program will be attached (must not be empty)
//
// Returns:
//   - *ebpf.Collection: The loaded eBPF collection containing programs and maps
//   - link.Link: The link representing the attachment to the cgroup
//
// The function will call t.Fatal if any error occurs during loading or attachment.
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

// get_local_ipv4 returns the local IPv4 address of the machine by establishing
// a connection to an external server (8.8.8.8:53, Google's DNS).
// This method determines which network interface is used for external communication.
//
// The function fails the test if:
// - It cannot establish a connection to the external server
// - It cannot extract the host part from the local address
//
// Parameters:
//   - t *testing.T: The testing object for reporting test failures
//
// Returns:
//   - string: The local IPv4 address (without port)
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
