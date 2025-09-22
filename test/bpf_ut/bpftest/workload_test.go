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
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	sync "sync"
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
	t.Run("SendMsg", testSendMsg)
	t.Run("CgroupSkb", testCgroupSkb)
	t.Run("CgroupSock", testCgroupSock)
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
func testSendMsg(t *testing.T) {
	tests := []unitTests_BUILD_CONTEXT{
		{
			objFilename: "workload_sendmsg_test.o",
			uts: []unitTest_BUILD_CONTEXT{
				{
					//eg:[0x01][00 00 00 06][08 08 08 08][00 35][0xFE][00 00 00 00]...
					name: "IPV4_TLV",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						//load the eBPF program
						spec := loadAndPrepSpec(t, path.Join(*testPath, objFilePath))
						var (
							coll *ebpf.Collection
							err  error
						)
						t.Log(path.Join(*testPath, objFilePath))
						//Load the eBPF collection into the kernel
						coll, err = ebpf.NewCollection(spec)
						if err != nil {
							var ve *ebpf.VerifierError
							if errors.As(err, &ve) {
								t.Fatalf("verifier error: %+v", ve)
							} else {
								t.Fatal("loading collection:", err)
							}
						}
						defer coll.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						var wg sync.WaitGroup
						wg.Add(1)
						// Get the sockhash and the program
						sockMap := coll.Maps["map_of_kmesh_sendmsg"]
						prog := coll.Programs["sendmsg_prog"]
						if sockMap == nil || prog == nil {
							t.Fatal("sockMap or sendmsg_prog not found")
						}
						//Attach sendmsg_prog to sockhash
						err = link.RawAttachProgram(link.RawAttachProgramOptions{
							Attach:  ebpf.AttachSkMsgVerdict,
							Target:  sockMap.FD(),
							Program: prog,
						})

						if err != nil {
							var errno syscall.Errno
							if errors.As(err, &errno) {
								t.Fatalf("Attach failed: %v (errno=%d)", err, errno)
							} else {
								t.Fatalf("Attach failed: %v", err)
							}
						}
						localIP := get_local_ipv4(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := localIP + ":" + strconv.Itoa(serverPort)
						listener, err := net.Listen("tcp4", serverSocket)
						if err != nil {
							t.Fatalf("Failed to start TCP server: %v", err)
						}
						defer listener.Close()

						go func() {
							defer wg.Done()
							conn, err := listener.Accept()
							if err != nil {
								t.Error(err)
								return
							}
							defer conn.Close()

							buf := make([]byte, 256)
							n, err := conn.Read(buf)
							if err != nil {
								t.Error(err)
								return
							}
							t.Logf("Server received data: % x", buf[:n])
							//check
							expectedIP := net.IPv4(8, 8, 8, 8)
							expectedPort := uint16(53)

							err = ValidateTLVMessage(t, buf[:n], expectedIP, expectedPort)
							if err != nil {
								t.Errorf("TLV validation failed: %v", err)
							}
						}()
						// try to connect to the server using the specified client port
						conn, err := (&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp4", serverSocket)
						if err != nil {
							t.Fatalf("Dial failed: %v", err)
						}
						defer conn.Close()
						//Get fd
						fd, err := getSysFd(conn)
						if err != nil {
							t.Fatal(err)
						}
						//Insert data into sockmap
						type bpfSockTuple4 struct {
							Saddr [4]byte
							Daddr [4]byte
							Sport uint16
							Dport uint16
							_     [24]byte
						}
						var tupleKey bpfSockTuple4
						copy(tupleKey.Saddr[:], net.ParseIP(localIP).To4())
						copy(tupleKey.Daddr[:], net.ParseIP(localIP).To4())
						tupleKey.Sport = uint16(htons(uint16(clientPort)))
						tupleKey.Dport = uint16(htons(uint16(serverPort)))
						fd32 := uint32(fd)
						err = sockMap.Update(&tupleKey, &fd32, ebpf.UpdateAny)
						if err != nil {
							t.Fatalf("failed to update sockhash: %v", err)
						} else {
							t.Logf("Update successful for key: %+v, fd: %d", tupleKey, fd32)
						}
						//Send data to trigger
						_, err = conn.Write([]byte("hello eBPF"))
						if err != nil {
							t.Fatal(err)
						}
						wg.Wait()
					},
				},
				{
					//eg:[0x01][00 00 00 12][fc 00 de ad be ef 12 34 00 00 00 00 00 00 ab cd][00 35][0xFE][00 00 00 00]
					name: "IPV6_TLV",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						var wg sync.WaitGroup
						wg.Add(1)

						//load the eBPF program
						spec := loadAndPrepSpec(t, path.Join(*testPath, objFilePath))
						var (
							coll *ebpf.Collection
							err  error
						)
						t.Log(path.Join(*testPath, objFilePath))
						//Load the eBPF collection into the kernel
						coll, err = ebpf.NewCollection(spec)
						if err != nil {
							var ve *ebpf.VerifierError
							if errors.As(err, &ve) {
								t.Fatalf("verifier error: %+v", ve)
							} else {
								t.Fatal("loading collection:", err)
							}
						}
						defer coll.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						//Retrieve the sockhash and the program
						sockMap := coll.Maps["map_of_kmesh_sendmsg"]
						prog := coll.Programs["sendmsg_prog"]
						if sockMap == nil || prog == nil {
							t.Fatal("sockMap or sendmsg_prog not found")
						}
						//Attach sendmsg_prog to sockhash
						err = link.RawAttachProgram(link.RawAttachProgramOptions{
							Attach:  ebpf.AttachSkMsgVerdict,
							Target:  sockMap.FD(),
							Program: prog,
						})

						if err != nil {
							var errno syscall.Errno
							if errors.As(err, &errno) {
								t.Fatalf("Attach failed: %v (errno=%d)", err, errno)
							} else {
								t.Fatalf("Attach failed: %v", err)
							}
						}

						localIP := get_local_ipv6(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := "[" + localIP + "]" + ":" + strconv.Itoa(serverPort)
						listener, err := net.Listen("tcp6", serverSocket)
						if err != nil {
							t.Fatalf("Failed to start TCP server: %v", err)
						}
						defer listener.Close()
						go func() {
							defer wg.Done()
							conn, err := listener.Accept()
							if err != nil {
								t.Error(err)
								return
							}
							defer conn.Close()

							buf := make([]byte, 256)
							n, err := conn.Read(buf)
							if err != nil {
								t.Error(err)
								return
							}
							t.Logf("Server received data: % x", buf[:n])
							expectedIP := net.ParseIP("fc00:dead:beef:1234::abcd")
							expectedPort := uint16(53)

							err = ValidateTLVMessage(t, buf[:n], expectedIP, expectedPort)
							if err != nil {
								t.Errorf("TLV validation failed: %v", err)
							}
						}()

						// try to connect to the server using the specified client port
						conn, err := (&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp6", serverSocket)
						if err != nil {
							t.Logf("accept failed: %v", err)
							return
						}
						defer conn.Close()
						// get  fd
						fd, err := getSysFd(conn)
						if err != nil {
							t.Fatal(err)
						}
						//insert sockmap
						type bpfSockTuple6 struct {
							Saddr [16]byte
							Daddr [16]byte
							Sport uint16
							Dport uint16
						}
						var tupleKey bpfSockTuple6
						copy(tupleKey.Saddr[:], net.ParseIP(localIP).To16())
						copy(tupleKey.Daddr[:], net.ParseIP(localIP).To16())
						tupleKey.Sport = uint16(htons(uint16(clientPort)))
						tupleKey.Dport = uint16(htons(uint16(serverPort)))
						// pass fd
						fd32 := uint32(fd)
						err = sockMap.Update(&tupleKey, &fd32, ebpf.UpdateAny)
						if err != nil {
							t.Fatalf("failed to update sockhash: %v", err)
						} else {
							t.Logf("Update successful for key: %+v, fd: %d", tupleKey, fd32)
						}
						//Send data to trigger
						_, err = conn.Write([]byte("hello eBPF"))
						if err != nil {
							t.Fatal(err)
						}
						wg.Wait()
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.objFilename, tt.run())
	}
}

// getSysFd extracts the underlying socket file descriptor from a Go net.Conn.
// This function is essential for eBPF testing as it allows registration of sockets
// in eBPF sockhash maps, which require raw file descriptors as values.
//
// Parameters:
//   - conn: Go network connection (must implement syscall.Conn interface)
//
// Returns:
//   - int: Socket file descriptor
//   - error: Error if extraction fails or conn doesn't support syscall operations
//
// The function will return an error if the connection doesn't implement syscall.Conn
// or if any syscall operations fail during file descriptor extraction.
func getSysFd(conn net.Conn) (int, error) {
	rawConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, fmt.Errorf("conn does not implement syscall.Conn")
	}
	rc, err := rawConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("SyscallConn() failed: %v", err)
	}
	var fd int
	err = rc.Control(func(s uintptr) {
		fd = int(s)
	})
	if err != nil {
		return 0, fmt.Errorf("Control() failed: %v", err)
	}
	return fd, nil
}

// htons converts a 16-bit integer from host byte order to network byte order.
// This function implements the standard htons() conversion required for eBPF map
// keys, ensuring consistent cross-platform byte ordering in network operations.
//
// Parameters:
//   - i: 16-bit integer in host byte order (typically port numbers)
//
// Returns:
//   - uint16: 16-bit integer converted to network byte order (big-endian)
//
// This conversion is necessary when storing port numbers in eBPF map keys, as
// eBPF maps expect network byte order for proper key matching.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// get_local_ipv6 discovers the machine's local IPv6 address suitable for testing.
// The function establishes a test connection to a known IPv6 address and extracts
// the local IPv6 address that the kernel selects for routing.
//
// Parameters:
//   - t: Testing context for logging and test control
//
// Returns:
//   - string: Local IPv6 address without port number
//
// The function will skip the test if IPv6 networking is not available or reachable.
// It will call t.Fatal if address extraction fails after successful connection.
func get_local_ipv6(t *testing.T) string {
	testConn, testErr := net.Dial("tcp6", "[2001:4860:4860::8888]:53")
	if testErr != nil {
		t.Skipf("Skipping IPv6 test: network not reachable (%v)", testErr)
	}
	defer testConn.Close()

	localAddr, _, err := net.SplitHostPort(testConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Failed to extract host from address: %v", err)
	}
	t.Log(localAddr)
	return localAddr
}

func testCgroupSkb(t *testing.T) {
	tests := []unitTests_BUILD_CONTEXT{
		{
			objFilename: "workload_cgroup_skb_test.o",
			uts: []unitTest_BUILD_CONTEXT{
				{
					name: "CgroupIngress_observe_on_data",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_skb_ingress_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:          constants.BPF_LOG_DEBUG,
							AuthzOffload:         constants.DISABLED,
							EnablePeriodicReport: constants.ENABLED,
						})
						startLogReader(coll)

						varName := "current_direction"
						currentDirVar, ok := coll.Variables[varName]
						if !ok {
							t.Fatalf("BPF variable %s not found", varName)
						}

						newDirection := uint32(1) // ingress
						if err := currentDirVar.Set(newDirection); err != nil {
							t.Fatalf("Failed to set %s: %v", varName, err)
						}
						localIP := get_local_ipv4(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := localIP + ":" + strconv.Itoa(serverPort)
						// Get the km_manage map from the collection
						kmManageMap := coll.Maps["km_manage"]
						if kmManageMap == nil {
							t.Fatal("Failed to get km_manage map from collection")
						}
						var (
							key   [16]byte
							value uint32
						)
						ip := net.ParseIP(localIP).To4()
						if ip == nil {
							t.Fatalf("invalid ipv4: %s", localIP)
						}
						binary.BigEndian.PutUint32(key[0:4], binary.BigEndian.Uint32(ip))
						value = 0
						if err := kmManageMap.Update(key, value, ebpf.UpdateAny); err != nil {
							t.Fatalf("Failed to update km_manage map: %v", err)
						}
						t.Logf("Inserted key: %d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])

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
						kmTcpProbeMap := coll.Maps["km_tcp_probe"]
						if kmTcpProbeMap == nil {
							t.Fatal("Failed to get km_auth_req map from collection")
						}

						rd, err := ringbuf.NewReader(kmTcpProbeMap)
						if err != nil {
							t.Fatalf("Failed to create ringbuf reader: %v", err)
						}
						defer rd.Close()

						record, err := rd.Read()
						if err != nil {
							t.Fatalf("Failed to read from ringbuf: %v", err)
						}

						type bpfSockTuple struct {
							Ipv4 struct {
								Saddr uint32
								Daddr uint32
								Sport uint16
								Dport uint16
							}
							Padding [24]byte
						}

						type origDstInfo struct {
							Ipv4 struct {
								Addr uint32
								Port uint16
							}
							Padding [14]byte
						}

						type tcpProbeInfo struct {
							Type          uint32
							Tuple         bpfSockTuple
							OrigDst       origDstInfo
							SentBytes     uint32
							ReceivedBytes uint32
							ConnSuccess   uint32
							Direction     uint32
							State         uint32
							Duration      uint64
							StartNs       uint64
							LastReportNs  uint64
							Protocol      uint32
							SrttUs        uint32
							RttMin        uint32
							TotalRetrans  uint32
							LostOut       uint32
							Padding       [4]byte
						}

						var info tcpProbeInfo
						if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &info); err != nil {
							log.Printf("parsing ringbuf event: %s", err)
						} else {
							fmt.Printf("tcp_probe_info:\n")
							fmt.Printf("  type           : %d\n", info.Type)
							fmt.Printf("  tuple.ipv4.saddr: %s\n", printIPv4(info.Tuple.Ipv4.Saddr))
							fmt.Printf("  tuple.ipv4.daddr: %s\n", printIPv4(info.Tuple.Ipv4.Daddr))
							fmt.Printf("  tuple.ipv4.sport: %d\n", info.Tuple.Ipv4.Sport)
							fmt.Printf("  tuple.ipv4.dport: %d\n", info.Tuple.Ipv4.Dport)
							fmt.Printf("  orig_dst.ipv4.addr: %s\n", printIPv4(info.OrigDst.Ipv4.Addr))
							fmt.Printf("  orig_dst.ipv4.port: %d\n", info.OrigDst.Ipv4.Port)
							fmt.Printf("  sent_bytes     : %d\n", info.SentBytes)
							fmt.Printf("  received_bytes : %d\n", info.ReceivedBytes)
							fmt.Printf("  conn_success   : %d\n", info.ConnSuccess)
							fmt.Printf("  direction      : %d\n", info.Direction)
							fmt.Printf("  state          : %d\n", info.State)
							fmt.Printf("  duration       : %d\n", info.Duration)
							fmt.Printf("  start_ns       : %d\n", info.StartNs)
							fmt.Printf("  last_report_ns : %d\n", info.LastReportNs)
							fmt.Printf("  protocol       : %d\n", info.Protocol)
							fmt.Printf("  srtt_us        : %d\n", info.SrttUs)
							fmt.Printf("  rtt_min        : %d\n", info.RttMin)
							fmt.Printf("  total_retrans  : %d\n", info.TotalRetrans)
							fmt.Printf("  lost_out       : %d\n", info.LostOut)
						}
					}},
				{
					name: "CgroupEgress_observe_on_data",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_skb_egress_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:          constants.BPF_LOG_DEBUG,
							AuthzOffload:         constants.DISABLED,
							EnablePeriodicReport: constants.ENABLED,
						})
						startLogReader(coll)

						varName := "current_direction"
						currentDirVar, ok := coll.Variables[varName]
						if !ok {
							t.Fatalf("BPF variable %s not found", varName)
						}

						newDirection := uint32(2) // egress
						if err := currentDirVar.Set(newDirection); err != nil {
							t.Fatalf("Failed to set %s: %v", varName, err)
						}

						localIP := get_local_ipv4(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := localIP + ":" + strconv.Itoa(serverPort)

						// Get the km_manage map from the collection
						kmManageMap := coll.Maps["km_manage"]
						if kmManageMap == nil {
							t.Fatal("Failed to get km_manage map from collection")
						}
						var (
							key   [16]byte
							value uint32
						)
						ip := net.ParseIP(localIP).To4()
						if ip == nil {
							t.Fatalf("invalid ipv4: %s", localIP)
						}
						binary.BigEndian.PutUint32(key[0:4], binary.BigEndian.Uint32(ip))
						value = 0
						if err := kmManageMap.Update(key, value, ebpf.UpdateAny); err != nil {
							t.Fatalf("Failed to update km_manage map: %v", err)
						}
						t.Logf("Inserted key: %d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])

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
						kmTcpProbeMap := coll.Maps["km_tcp_probe"]
						if kmTcpProbeMap == nil {
							t.Fatal("Failed to get km_auth_req map from collection")
						}

						rd, err := ringbuf.NewReader(kmTcpProbeMap)
						if err != nil {
							t.Fatalf("Failed to create ringbuf reader: %v", err)
						}
						defer rd.Close()

						record, err := rd.Read()
						if err != nil {
							t.Fatalf("Failed to read from ringbuf: %v", err)
						}
						type bpfSockTuple struct {
							Ipv4 struct {
								Saddr uint32
								Daddr uint32
								Sport uint16
								Dport uint16
							}
							Padding [24]byte
						}

						type origDstInfo struct {
							Ipv4 struct {
								Addr uint32
								Port uint16
							}
							Padding [14]byte
						}

						type tcpProbeInfo struct {
							Type          uint32
							Tuple         bpfSockTuple
							OrigDst       origDstInfo
							SentBytes     uint32
							ReceivedBytes uint32
							ConnSuccess   uint32
							Direction     uint32
							State         uint32
							Duration      uint64
							StartNs       uint64
							LastReportNs  uint64
							Protocol      uint32
							SrttUs        uint32
							RttMin        uint32
							TotalRetrans  uint32
							LostOut       uint32
							Padding       [4]byte
						}

						var info tcpProbeInfo
						if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &info); err != nil {
							log.Printf("parsing ringbuf event: %s", err)
						} else {
							fmt.Printf("tcp_probe_info:\n")
							fmt.Printf("  type           : %d\n", info.Type)
							fmt.Printf("  tuple.ipv4.saddr: %s\n", printIPv4(info.Tuple.Ipv4.Saddr))
							fmt.Printf("  tuple.ipv4.daddr: %s\n", printIPv4(info.Tuple.Ipv4.Daddr))
							fmt.Printf("  tuple.ipv4.sport: %d\n", info.Tuple.Ipv4.Sport)
							fmt.Printf("  tuple.ipv4.dport: %d\n", info.Tuple.Ipv4.Dport)
							fmt.Printf("  orig_dst.ipv4.addr: %s\n", printIPv4(info.OrigDst.Ipv4.Addr))
							fmt.Printf("  orig_dst.ipv4.port: %d\n", info.OrigDst.Ipv4.Port)
							fmt.Printf("  sent_bytes     : %d\n", info.SentBytes)
							fmt.Printf("  received_bytes : %d\n", info.ReceivedBytes)
							fmt.Printf("  conn_success   : %d\n", info.ConnSuccess)
							fmt.Printf("  direction      : %d\n", info.Direction)
							fmt.Printf("  state          : %d\n", info.State)
							fmt.Printf("  duration       : %d\n", info.Duration)
							fmt.Printf("  start_ns       : %d\n", info.StartNs)
							fmt.Printf("  last_report_ns : %d\n", info.LastReportNs)
							fmt.Printf("  protocol       : %d\n", info.Protocol)
							fmt.Printf("  srtt_us        : %d\n", info.SrttUs)
							fmt.Printf("  rtt_min        : %d\n", info.RttMin)
							fmt.Printf("  total_retrans  : %d\n", info.TotalRetrans)
							fmt.Printf("  lost_out       : %d\n", info.LostOut)
						}
					}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.objFilename, tt.run())
	}
}

// converts a uint32 IPv4 address into a dotted-decimal string

func load_bpf_prog_to_cgroup(t *testing.T, objFilename string, progName string, cgroupPath string) (*ebpf.Collection, link.Link) {
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
		Path:    cgroupPath,
		Attach:  spec.Programs[progName].AttachType,
		Program: coll.Programs[progName],
	})
	t.Log(spec.Programs[progName].AttachType)
	if err != nil {
		coll.Close()
		t.Fatalf("Failed to attach cgroup: %v", err)
	}
	return coll, lk
}
func printIPv4(ip uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return net.IP(b).String()
}

func testCgroupSock(t *testing.T) {
	tests := []unitTests_BUILD_CONTEXT{
		{
			objFilename: "workload_cgroup_sock_test.o",
			uts: []unitTest_BUILD_CONTEXT{
				{
					name: "BPF_CGROUP_SOCK_CONNECT4_handle_kmesh_manage_process",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect4_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_netns_cookie
						enableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperEnableControl))
						net.DialTimeout("tcp4", enableAddr, 2*time.Second)
						// Get the km_manage map from the collection
						kmManageMap := coll.Maps["km_manage"]
						if kmManageMap == nil {
							t.Fatal("Failed to get km_manage map from collection")
						}
						var (
							key   [16]byte
							value uint32
						)

						iter := kmManageMap.Iterate()
						count := 0

						for iter.Next(&key, &value) {
							netnsCookie := binary.LittleEndian.Uint64(key[:8])
							t.Logf("Entry %d: netns_cookie=%d, value=%d", count+1, netnsCookie, value)
							count++
						}
						if err := iter.Err(); err != nil {
							t.Fatalf("Iterate error: %v", err)
						}

						if count != 1 {
							t.Fatalf("Expected 1 entry in km_manage map, but got %d", count)
						}
						// remove_kmesh_managed_netns_cookie
						disableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperDisableControl))
						net.DialTimeout("tcp4", disableAddr, 2*time.Second)

						iter = kmManageMap.Iterate()
						count = 0
						for iter.Next(&key, &value) {
							count++
						}

						if err := iter.Err(); err != nil {
							t.Fatalf("Iterate error: %v", err)
						}
						if count != 0 {
							t.Fatalf("Expected 0 entry in km_manage map, but got %d", count)
						}
					}},
				{
					name: "BPF_CGROUP_SOCK_CONNECT4_backend_no_waypoint",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect4_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_netns_cookie
						localIP := get_local_ipv4(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := localIP + ":" + strconv.Itoa(serverPort)
						// record_kmesh_managed_ip
						enableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperEnableControl))
						(&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp4", enableAddr)
						//populate the frontend map
						type ip_addr struct {
							Raw [16]byte
						}

						type frontend_key struct {
							Addr ip_addr
						}

						type frontend_value struct {
							UpstreamID uint32
						}

						FrontendMap := coll.Maps["km_frontend"]
						var f_key frontend_key
						ip4 := net.ParseIP(localIP).To4()
						if ip4 == nil {
							t.Fatalf("invalid IPv4 address")
						}
						copy(f_key.Addr.Raw[0:4], ip4)
						//construct the value
						f_val := frontend_value{
							UpstreamID: 1,
						}
						if err := FrontendMap.Update(&f_key, &f_val, ebpf.UpdateAny); err != nil {
							t.Fatalf("Update failed: %v", err)
						}
						//populate the km_backend
						BackendMap := coll.Maps["km_backend"]
						const MAX_SERVICE_COUNT = 10
						type backend_key struct {
							BackendUID uint32
						}

						type backend_value struct {
							Addr         ip_addr
							ServiceCount uint32
							Service      [MAX_SERVICE_COUNT]uint32
							WpAddr       ip_addr
							WaypointPort uint32
						}
						//construct the key
						b_key := backend_key{
							BackendUID: 1,
						}
						//construct the value
						b_val := backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: 0,
						}

						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							t.Fatalf("Update failed: %v", err)
						}
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
							t.Fatalf("Failed to connect to TCP server: %v", serverSocket)
						}
						defer conn.Close()
						//check
						remoteAddr := conn.RemoteAddr().String()
						t.Logf("Actual connected to: %s", remoteAddr)

						host, port, err := net.SplitHostPort(remoteAddr)
						if err != nil {
							t.Fatalf("Failed to parse remote address: %v", err)
						}
						expectedIP := localIP
						expectedPort := strconv.Itoa(serverPort)

						if host != expectedIP || port != expectedPort {
							t.Fatalf("Expected redirected to %s:%s, but got %s:%s", expectedIP, expectedPort, host, port)
						}
					}},
				{
					name: "BPF_CGROUP_SOCK_CONNECT4_backend_yes_waypoint",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect4_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_netns_cookie
						localIP := get_local_ipv4(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := localIP + ":" + strconv.Itoa(serverPort)
						var testPort uint16 = 55555
						testIpPort := localIP + ":" + strconv.Itoa(int(htons(testPort)))
						testListener, err := net.Listen("tcp4", testIpPort)
						if err != nil {
							t.Fatalf("Failed to listen on test port %s: %v", testIpPort, err)
						}
						defer testListener.Close()
						// record_kmesh_managed_ip
						enableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperEnableControl))

						(&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp4", enableAddr)
						//populate the frontend map
						type ip_addr struct {
							Raw [16]byte
						}

						type frontend_key struct {
							Addr ip_addr
						}

						type frontend_value struct {
							UpstreamID uint32
						}

						FrontendMap := coll.Maps["km_frontend"]
						var f_key frontend_key
						ip4 := net.ParseIP(localIP).To4()
						if ip4 == nil {
							t.Fatalf("invalid IPv4 address")
						}
						copy(f_key.Addr.Raw[0:4], ip4)
						//construct the value
						f_val := frontend_value{
							UpstreamID: 1,
						}
						if err := FrontendMap.Update(&f_key, &f_val, ebpf.UpdateAny); err != nil {
							t.Fatalf("Update failed: %v", err)
						}
						//populate km_backend
						BackendMap := coll.Maps["km_backend"]
						const MAX_SERVICE_COUNT = 10
						type backend_key struct {
							BackendUID uint32
						}

						type backend_value struct {
							Addr         ip_addr
							ServiceCount uint32
							Service      [MAX_SERVICE_COUNT]uint32
							WpAddr       ip_addr
							WaypointPort uint32
						}
						//construct the key
						b_key := backend_key{
							BackendUID: 1,
						}
						wpIP := net.ParseIP(localIP).To4()
						//construct the value
						b_val := backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: uint32(testPort),
						}
						//populate WpAddr
						copy(b_val.WpAddr.Raw[0:4], wpIP)
						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							t.Fatalf("Update failed: %v", err)
						}
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
							t.Fatalf("Dial failed: %v", err)
						}
						defer conn.Close()
						//check
						remoteAddr := conn.RemoteAddr().String()
						t.Logf("Actual connected to: %s", remoteAddr)

						host, port, err := net.SplitHostPort(remoteAddr)
						if err != nil {
							t.Fatalf("Failed to parse remote address: %v", err)
						}
						expectedIP := localIP
						expectedPort := strconv.Itoa(int(htons(testPort)))

						if host != expectedIP || port != expectedPort {
							t.Fatalf("Expected redirected to %s:%s, but got %s:%s", expectedIP, expectedPort, host, port)
						}
					}},
				{
					name: "BPF_CGROUP_SOCK_CONNECT4_service_yes_waypoint",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect4_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_netns_cookie
						localIP := get_local_ipv4(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := localIP + ":" + strconv.Itoa(serverPort)
						var testPort uint16 = 55555
						testIpPort := localIP + ":" + strconv.Itoa(int(htons(testPort)))
						testListener, err := net.Listen("tcp4", testIpPort)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener.Close()
						// record_kmesh_managed_ip
						enableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperEnableControl))
						(&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp4", enableAddr)
						//insert frontend map
						type ip_addr struct {
							Raw [16]byte
						}
						type frontend_key struct {
							Addr ip_addr
						}
						type frontend_value struct {
							UpstreamID uint32
						}
						FrontendMap := coll.Maps["km_frontend"]
						var f_key frontend_key
						ip4 := net.ParseIP(localIP).To4()
						if ip4 == nil {
							t.Fatalf("invalid IPv4 address")
						}
						copy(f_key.Addr.Raw[0:4], ip4)
						// insert value
						f_val := frontend_value{
							UpstreamID: 1,
						}
						if err := FrontendMap.Update(&f_key, &f_val, ebpf.UpdateAny); err != nil {
							t.Fatalf("Update failed: %v", err)
						}
						ServiceMap := coll.Maps["km_service"]
						type service_key struct {
							ServiceID uint32
						}

						type service_value struct {
							PrioEndpointCount [7]uint32
							LbPolicy          uint32
							ServicePort       [10]uint32
							TargetPort        [10]uint32
							WpAddr            ip_addr
							WaypointPort      uint32
						}
						//insert key
						s_key := service_key{
							ServiceID: 1,
						}

						wpIP := net.ParseIP(localIP).To4()
						//insert value
						s_val := service_value{
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: uint32(testPort),
						}
						//insert WpAddr
						copy(s_val.WpAddr.Raw[0:4], wpIP)
						if err := ServiceMap.Update(&s_key, &s_val, ebpf.UpdateAny); err != nil {
							t.Fatalf("Update failed: %v", err)
						}

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
							t.Fatalf("Dial failed: %v", err)
						}
						defer conn.Close()
						//check
						remoteAddr := conn.RemoteAddr().String()
						t.Logf("Actual connected to: %s", remoteAddr)

						host, port, err := net.SplitHostPort(remoteAddr)
						if err != nil {
							t.Fatalf("Failed to parse remote address: %v", err)
						}
						expectedIP := localIP
						expectedPort := strconv.Itoa(int(htons(testPort)))

						if host != expectedIP || port != expectedPort {
							t.Fatalf("Expected redirected to %s:%s, but got %s:%s", expectedIP, expectedPort, host, port)
						}
					}},
				{
					name: "BPF_CGROUP_SOCK_CONNECT4_service_no_waypoint_lb_random_handle",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect4_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_netns_cookie
						localIP := get_local_ipv4(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := localIP + ":" + strconv.Itoa(serverPort)
						var testPort1 uint16 = 55555
						testIpPort1 := localIP + ":" + strconv.Itoa(int(htons(testPort1)))
						testListener1, err := net.Listen("tcp4", testIpPort1)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener1.Close()
						var testPort2 uint16 = 55556
						testIpPort2 := localIP + ":" + strconv.Itoa(int(htons(testPort2)))
						testListener2, err := net.Listen("tcp4", testIpPort2)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener2.Close()

						// record_kmesh_managed_ip
						enableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperEnableControl))
						(&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp4", enableAddr)

						//frontend map
						type ip_addr struct {
							Raw [16]byte
						}
						type frontend_key struct {
							Addr ip_addr
						}
						type frontend_value struct {
							UpstreamID uint32
						}
						FrontendMap := coll.Maps["km_frontend"]
						var f_key frontend_key

						ip4 := net.ParseIP(localIP).To4()
						if ip4 == nil {
							t.Fatalf("invalid IPv4 address")
						}
						copy(f_key.Addr.Raw[0:4], ip4)
						//value
						f_val := frontend_value{
							UpstreamID: 1,
						}
						if err := FrontendMap.Update(&f_key, &f_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//service map
						ServiceMap := coll.Maps["km_service"]
						const MAX_SERVICE_COUNT = 10
						type service_key struct {
							ServiceID uint32
						}
						type service_value struct {
							PrioEndpointCount [7]uint32
							LbPolicy          uint32
							ServicePort       [10]uint32
							TargetPort        [10]uint32
							WpAddr            ip_addr
							WaypointPort      uint32
						}
						//key
						s_key := service_key{
							ServiceID: 1,
						}
						wpIP := net.ParseIP(localIP).To4()
						s_val := service_value{
							LbPolicy: 0,
							PrioEndpointCount: [7]uint32{
								2, 0, 0, 0, 0, 0, 0,
							},
							ServicePort: [10]uint32{
								uint32(htons(uint16(serverPort))), 0, 0, 0, 0, 0, 0, 0, 0, 0,
							},
							TargetPort: [10]uint32{
								uint32(testPort2),
							},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: 0,
						}
						// WpAddr
						copy(s_val.WpAddr.Raw[0:4], wpIP)
						if err := ServiceMap.Update(&s_key, &s_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//endpoint
						type endpoint_key struct {
							service_id    uint32
							prio          uint32
							backend_index uint32 //rand_k
						}
						type endpoint_value struct {
							backend_uid uint32
						}
						//1
						e_key := endpoint_key{
							service_id:    1,
							prio:          0,
							backend_index: 1,
						}
						e_val := endpoint_value{
							backend_uid: 2,
						}
						EndpointMap := coll.Maps["km_endpoint"]
						if err := EndpointMap.Update(&e_key, &e_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}
						//2
						e_key = endpoint_key{
							service_id:    1,
							prio:          0,
							backend_index: 2,
						}
						e_val = endpoint_value{
							backend_uid: 6,
						}
						if err := EndpointMap.Update(&e_key, &e_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//backend
						BackendMap := coll.Maps["km_backend"]
						type backend_key struct {
							BackendUID uint32
						}

						type backend_value struct {
							Addr         ip_addr
							ServiceCount uint32
							Service      [MAX_SERVICE_COUNT]uint32
							WpAddr       ip_addr
							WaypointPort uint32
						}
						//1
						b_key := backend_key{
							BackendUID: 2,
						}
						wpIP = net.ParseIP(localIP).To4()
						b_val := backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: uint32(testPort1),
						}
						copy(b_val.WpAddr.Raw[0:4], wpIP)
						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}
						//2
						b_key = backend_key{
							BackendUID: 6,
						}
						IP := net.ParseIP(localIP).To4()
						b_val = backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: 0,
						}
						copy(b_val.Addr.Raw[0:4], IP)
						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

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
							t.Fatalf("Dial failed: %v", err)
						}
						defer conn.Close()
						//test
						remoteAddr := conn.RemoteAddr().String()
						t.Logf("Actual connected to: %s", remoteAddr)
						host, port, err := net.SplitHostPort(remoteAddr)
						if err != nil {
							t.Fatalf("Failed to parse remote address: %v", err)
						}
						t.Logf("Host: %s, Port: %s", host, port)
					}},
				{
					name: "BPF_CGROUP_SOCK_CONNECT4_service_no_waypoint_lb_locality_strict_handle",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect4_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_netns_cookie
						localIP := get_local_ipv4(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := localIP + ":" + strconv.Itoa(serverPort)
						var testPort1 uint16 = 55555
						testIpPort1 := localIP + ":" + strconv.Itoa(int(htons(testPort1)))
						testListener1, err := net.Listen("tcp4", testIpPort1)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener1.Close()
						var testPort2 uint16 = 55556
						testIpPort2 := localIP + ":" + strconv.Itoa(int(htons(testPort2)))
						testListener2, err := net.Listen("tcp4", testIpPort2)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener2.Close()

						// record_kmesh_managed_ip
						enableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperEnableControl))
						(&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp4", enableAddr)

						//frontend map
						type ip_addr struct {
							Raw [16]byte
						}
						type frontend_key struct {
							Addr ip_addr
						}
						type frontend_value struct {
							UpstreamID uint32
						}
						FrontendMap := coll.Maps["km_frontend"]
						var f_key frontend_key

						ip4 := net.ParseIP(localIP).To4()
						if ip4 == nil {
							t.Fatalf("invalid IPv4 address")
						}
						copy(f_key.Addr.Raw[0:4], ip4)
						//value
						f_val := frontend_value{
							UpstreamID: 1,
						}
						if err := FrontendMap.Update(&f_key, &f_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//service map
						ServiceMap := coll.Maps["km_service"]
						const MAX_SERVICE_COUNT = 10
						type service_key struct {
							ServiceID uint32
						}
						type service_value struct {
							PrioEndpointCount [7]uint32
							LbPolicy          uint32
							ServicePort       [10]uint32
							TargetPort        [10]uint32
							WpAddr            ip_addr
							WaypointPort      uint32
						}
						//key
						s_key := service_key{
							ServiceID: 1,
						}
						wpIP := net.ParseIP(localIP).To4()
						s_val := service_value{
							LbPolicy: 0,
							PrioEndpointCount: [7]uint32{
								2, 0, 0, 0, 0, 0, 0,
							},
							ServicePort: [10]uint32{
								uint32(htons(uint16(serverPort))), 0, 0, 0, 0, 0, 0, 0, 0, 0,
							},
							TargetPort: [10]uint32{
								uint32(testPort2),
							},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: 0,
						}
						// WpAddr
						copy(s_val.WpAddr.Raw[0:4], wpIP)
						if err := ServiceMap.Update(&s_key, &s_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//endpoint
						type endpoint_key struct {
							service_id    uint32
							backend_index uint32 //rand_k
							prio          uint32
						}
						type endpoint_value struct {
							backend_uid uint32
						}
						//1
						e_key := endpoint_key{
							service_id:    1,
							backend_index: 1,
							prio:          0,
						}
						e_val := endpoint_value{
							backend_uid: 2,
						}
						EndpointMap := coll.Maps["km_endpoint"]
						if err := EndpointMap.Update(&e_key, &e_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}
						//2
						e_key = endpoint_key{
							service_id:    1,
							backend_index: 2,
							prio:          0,
						}
						e_val = endpoint_value{
							backend_uid: 6,
						}
						if err := EndpointMap.Update(&e_key, &e_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//backend
						BackendMap := coll.Maps["km_backend"]
						type backend_key struct {
							BackendUID uint32
						}

						type backend_value struct {
							Addr         ip_addr
							ServiceCount uint32
							Service      [MAX_SERVICE_COUNT]uint32
							WpAddr       ip_addr
							WaypointPort uint32
						}
						//1
						b_key := backend_key{
							BackendUID: 2,
						}
						wpIP = net.ParseIP(localIP).To4()
						b_val := backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: uint32(testPort1),
						}
						copy(b_val.WpAddr.Raw[0:4], wpIP)
						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}
						//2
						b_key = backend_key{
							BackendUID: 6,
						}
						IP := net.ParseIP(localIP).To4()
						b_val = backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: 0,
						}
						copy(b_val.Addr.Raw[0:4], IP)
						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

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
							t.Fatalf("Dial failed: %v", err)
						}
						defer conn.Close()
						//test
						remoteAddr := conn.RemoteAddr().String()
						t.Logf("Actual connected to: %s", remoteAddr)
						host, port, err := net.SplitHostPort(remoteAddr)
						if err != nil {
							t.Fatalf("Failed to parse remote address: %v", err)
						}
						t.Logf("Host: %s, Port: %s", host, port)
					}},
				{
					name: "BPF_CGROUP_SOCK_CONNECT4_service_no_waypoint_lb_locality_failover_handle",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect4_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_netns_cookie
						localIP := get_local_ipv4(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := localIP + ":" + strconv.Itoa(serverPort)
						var testPort1 uint16 = 55555
						testIpPort1 := localIP + ":" + strconv.Itoa(int(htons(testPort1)))
						testListener1, err := net.Listen("tcp4", testIpPort1)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener1.Close()
						var testPort2 uint16 = 55556
						testIpPort2 := localIP + ":" + strconv.Itoa(int(htons(testPort2)))
						testListener2, err := net.Listen("tcp4", testIpPort2)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener2.Close()

						// record_kmesh_managed_ip
						enableAddr := constants.ControlCommandIp4 + ":" + strconv.Itoa(int(constants.OperEnableControl))
						(&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp4", enableAddr)

						//frontend map
						type ip_addr struct {
							Raw [16]byte
						}
						type frontend_key struct {
							Addr ip_addr
						}
						type frontend_value struct {
							UpstreamID uint32
						}
						FrontendMap := coll.Maps["km_frontend"]
						var f_key frontend_key

						ip4 := net.ParseIP(localIP).To4()
						if ip4 == nil {
							t.Fatalf("invalid IPv4 address")
						}
						copy(f_key.Addr.Raw[0:4], ip4)
						//value
						f_val := frontend_value{
							UpstreamID: 1,
						}
						if err := FrontendMap.Update(&f_key, &f_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//service map
						ServiceMap := coll.Maps["km_service"]
						const MAX_SERVICE_COUNT = 10
						type service_key struct {
							ServiceID uint32
						}
						type service_value struct {
							PrioEndpointCount [7]uint32
							LbPolicy          uint32
							ServicePort       [10]uint32
							TargetPort        [10]uint32
							WpAddr            ip_addr
							WaypointPort      uint32
						}
						//key
						s_key := service_key{
							ServiceID: 1,
						}
						wpIP := net.ParseIP(localIP).To4()
						s_val := service_value{
							LbPolicy: 0,
							PrioEndpointCount: [7]uint32{
								0, 0, 0, 0, 0, 2, 0,
							},
							ServicePort: [10]uint32{
								uint32(htons(uint16(serverPort))), 0, 0, 0, 0, 0, 0, 0, 0, 0,
							},
							TargetPort: [10]uint32{
								uint32(testPort2),
							},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: 0,
						}
						// WpAddr
						copy(s_val.WpAddr.Raw[0:4], wpIP)
						if err := ServiceMap.Update(&s_key, &s_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//endpoint
						type endpoint_key struct {
							service_id    uint32
							prio          uint32
							backend_index uint32 //rand_k
						}
						type endpoint_value struct {
							backend_uid uint32
						}
						//1
						e_key := endpoint_key{
							service_id:    1,
							prio:          5,
							backend_index: 1,
						}
						e_val := endpoint_value{
							backend_uid: 2,
						}
						EndpointMap := coll.Maps["km_endpoint"]
						if err := EndpointMap.Update(&e_key, &e_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}
						//2
						e_key = endpoint_key{
							service_id:    1,
							prio:          5,
							backend_index: 2,
						}
						e_val = endpoint_value{
							backend_uid: 6,
						}
						if err := EndpointMap.Update(&e_key, &e_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//backend
						BackendMap := coll.Maps["km_backend"]
						type backend_key struct {
							BackendUID uint32
						}

						type backend_value struct {
							Addr         ip_addr
							ServiceCount uint32
							Service      [MAX_SERVICE_COUNT]uint32
							WpAddr       ip_addr
							WaypointPort uint32
						}
						//1
						b_key := backend_key{
							BackendUID: 2,
						}
						wpIP = net.ParseIP(localIP).To4()
						b_val := backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: uint32(testPort1),
						}
						copy(b_val.WpAddr.Raw[0:4], wpIP)
						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}
						//2
						b_key = backend_key{
							BackendUID: 6,
						}
						IP := net.ParseIP(localIP).To4()
						b_val = backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: 0,
						}
						copy(b_val.Addr.Raw[0:4], IP)
						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

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
							t.Fatalf("Dial failed: %v", err)
						}
						defer conn.Close()
						//test
						remoteAddr := conn.RemoteAddr().String()
						t.Logf("Actual connected to: %s", remoteAddr)
						host, port, err := net.SplitHostPort(remoteAddr)
						if err != nil {
							t.Fatalf("Failed to parse remote address: %v", err)
						}
						t.Logf("Host: %s, Port: %s", host, port)
					}},
				{
					name: "BPF_CGROUP_SOCK_CONNECT6_handle_kmesh_manage_process",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect6_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_netns_cookie
						enableAddr := "[" + constants.ControlCommandIp6 + "]" + ":" + strconv.Itoa(int(constants.OperEnableControl))
						net.DialTimeout("tcp6", enableAddr, 2*time.Second)
						// Get the km_manage map from the collection
						kmManageMap := coll.Maps["km_manage"]
						if kmManageMap == nil {
							t.Fatal("Failed to get km_manage map from collection")
						}
						var (
							key   [16]byte
							value uint32
						)

						iter := kmManageMap.Iterate()
						count := 0

						for iter.Next(&key, &value) {
							netnsCookie := binary.LittleEndian.Uint64(key[:8])
							t.Logf("Entry %d: netns_cookie=%d, value=%d", count+1, netnsCookie, value)
							count++
						}
						if err := iter.Err(); err != nil {
							t.Fatalf("Iterate error: %v", err)
						}

						if count != 1 {
							t.Fatalf("Expected 1 entry in km_manage map, but got %d", count)
						}
						// remove_kmesh_managed_netns_cookie
						disableAddr := "[" + constants.ControlCommandIp6 + "]" + ":" + strconv.Itoa(int(constants.OperDisableControl))
						net.DialTimeout("tcp6", disableAddr, 2*time.Second)
						iter = kmManageMap.Iterate()
						count = 0
						for iter.Next(&key, &value) {
							count++
						}

						if err := iter.Err(); err != nil {
							t.Fatalf("Iterate error: %v", err)
						}
						if count != 0 {
							t.Fatalf("Expected 0 entry in km_manage map, but got %d", count)
						}
					}},
				{
					name: "BPF_CGROUP_SOCK_CONNECT6_backend_no_waypoint",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect6_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_netns_cookie
						localIP := get_local_ipv6(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := "[" + localIP + "]" + ":" + strconv.Itoa(serverPort)
						// record_kmesh_managed_ip
						enableAddr := "[" + constants.ControlCommandIp6 + "]" + ":" + strconv.Itoa(int(constants.OperEnableControl))
						(&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp6", enableAddr)
						//Populate the frontend map with initial data
						type ip_addr struct {
							Raw [16]byte
						}

						type frontend_key struct {
							Addr ip_addr
						}

						type frontend_value struct {
							UpstreamID uint32
						}

						FrontendMap := coll.Maps["km_frontend"]
						var f_key frontend_key

						ip6 := net.ParseIP(localIP).To16()
						if ip6 == nil {
							t.Fatalf("invalid IPv6 address")
						}
						copy(f_key.Addr.Raw[:], ip6)

						f_val := frontend_value{
							UpstreamID: 1,
						}
						if err := FrontendMap.Update(&f_key, &f_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}
						BackendMap := coll.Maps["km_backend"]
						const MAX_SERVICE_COUNT = 10
						type backend_key struct {
							BackendUID uint32
						}

						type backend_value struct {
							Addr         ip_addr
							ServiceCount uint32
							Service      [MAX_SERVICE_COUNT]uint32
							WpAddr       ip_addr
							WaypointPort uint32
						}
						//Construct the key
						b_key := backend_key{
							BackendUID: 1,
						}
						//Construct the value
						b_val := backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: 0,
						}

						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						listener, err := net.Listen("tcp6", serverSocket)
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
						}).Dial("tcp6", serverSocket)
						if err != nil {
							t.Fatalf("Failed to connect to server: %v", err)
						}
						defer conn.Close()
						//test
						remoteAddr := conn.RemoteAddr().String()
						t.Logf("Actual connected to: %s", remoteAddr)

						//Parse IP and port
						host, port, err := net.SplitHostPort(remoteAddr)
						if err != nil {
							t.Fatalf("Failed to parse remote address: %v", err)
						}

						//Verify if it matches the expected IP and port
						expectedIP := localIP
						expectedPort := strconv.Itoa(serverPort)

						if host != expectedIP || port != expectedPort {
							t.Fatalf("Expected redirected to %s:%s, but got %s:%s", expectedIP, expectedPort, host, port)
						}
					}},
				{
					name: "BPF_CGROUP_SOCK_CONNECT6_backend_yes_waypoint",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect6_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_netns_cookie
						localIP := get_local_ipv6(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := "[" + localIP + "]" + ":" + strconv.Itoa(serverPort)
						var testPort uint16 = 55555
						testIpPort := "[" + localIP + "]" + ":" + strconv.Itoa(int(htons(testPort)))

						// record_kmesh_managed_ip
						enableAddr := "[" + constants.ControlCommandIp6 + "]" + ":" + strconv.Itoa(int(constants.OperEnableControl))

						testListener, err := net.Listen("tcp6", testIpPort)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener.Close()

						(&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp6", enableAddr)
						//Populate the frontend map
						type ip_addr struct {
							Raw [16]byte
						}

						type frontend_key struct {
							Addr ip_addr
						}

						type frontend_value struct {
							UpstreamID uint32
						}

						FrontendMap := coll.Maps["km_frontend"]
						var f_key frontend_key
						ip6 := net.ParseIP(localIP).To16()
						if ip6 == nil {
							t.Fatalf("invalid IPv6 address")
						}
						copy(f_key.Addr.Raw[:], ip6)
						//Construct the value
						f_val := frontend_value{
							UpstreamID: 1,
						}
						if err := FrontendMap.Update(&f_key, &f_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//Populate km_backend
						BackendMap := coll.Maps["km_backend"]
						const MAX_SERVICE_COUNT = 10
						type backend_key struct {
							BackendUID uint32
						}

						type backend_value struct {
							Addr         ip_addr
							ServiceCount uint32
							Service      [MAX_SERVICE_COUNT]uint32
							WpAddr       ip_addr
							WaypointPort uint32
						}
						//Construct the key
						b_key := backend_key{
							BackendUID: 1,
						}
						wpIP := net.ParseIP(localIP).To16()
						//Construct the value
						b_val := backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: uint32(testPort),
						}
						//Populate WpAddr
						copy(b_val.WpAddr.Raw[:], wpIP)
						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						listener, err := net.Listen("tcp6", serverSocket)
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
						}).Dial("tcp6", serverSocket)
						if err != nil {
							t.Fatalf("Dial failed: %v", err)
						}
						defer conn.Close()
						//test
						remoteAddr := conn.RemoteAddr().String()
						t.Logf("Actual connected to: %s", remoteAddr)

						//Parse IP and port
						host, port, err := net.SplitHostPort(remoteAddr)
						if err != nil {
							t.Fatalf("Failed to parse remote address: %v", err)
						}

						//Verify if it matches the expected IP and port
						expectedIP := localIP
						expectedPort := strconv.Itoa(int(htons(testPort)))

						if host != expectedIP || port != expectedPort {
							t.Fatalf("Expected redirected to %s:%s, but got %s:%s", expectedIP, expectedPort, host, port)
						}
					}},
				{
					name: "BPF_CGROUP_SOCK_CONNECT6_service_yes_waypoint",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect6_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_netns_cookie
						localIP := get_local_ipv6(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := "[" + localIP + "]" + ":" + strconv.Itoa(serverPort)
						var testPort uint16 = 55555
						testIpPort := "[" + localIP + "]" + ":" + strconv.Itoa(int(htons(testPort)))
						testListener, err := net.Listen("tcp6", testIpPort)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener.Close()
						// record_kmesh_managed_ip
						enableAddr := "[" + constants.ControlCommandIp6 + "]" + ":" + strconv.Itoa(int(constants.OperEnableControl))
						(&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp6", enableAddr)
						//Populate the frontend map
						type ip_addr struct {
							Raw [16]byte
						}
						type frontend_key struct {
							Addr ip_addr
						}
						type frontend_value struct {
							UpstreamID uint32
						}
						FrontendMap := coll.Maps["km_frontend"]
						var f_key frontend_key

						ip6 := net.ParseIP(localIP).To16()
						if ip6 == nil {
							t.Fatalf("invalid IPv4 address")
						}
						copy(f_key.Addr.Raw[:], ip6)
						//Construct the value
						f_val := frontend_value{
							UpstreamID: 1,
						}
						if err := FrontendMap.Update(&f_key, &f_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						ServiceMap := coll.Maps["km_service"]
						type service_key struct {
							ServiceID uint32
						}

						type service_value struct {
							PrioEndpointCount [7]uint32
							LbPolicy          uint32
							ServicePort       [10]uint32
							TargetPort        [10]uint32
							WpAddr            ip_addr
							WaypointPort      uint32
						}
						//Construct the key
						s_key := service_key{
							ServiceID: 1,
						}

						wpIP := net.ParseIP(localIP).To16()
						//Construct the value
						s_val := service_value{
							WpAddr:       ip_addr{Raw: [16]byte{}}, // waypoint IP全0，表示无
							WaypointPort: uint32(testPort),         //
						}
						//Construct the WpAddr
						copy(s_val.WpAddr.Raw[:], wpIP)

						if err := ServiceMap.Update(&s_key, &s_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						listener, err := net.Listen("tcp6", serverSocket)
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
						}).Dial("tcp6", serverSocket)
						if err != nil {
							t.Fatalf("Dial failed: %v", err)
						}
						defer conn.Close()
						//test
						remoteAddr := conn.RemoteAddr().String()
						t.Logf("Actual connected to: %s", remoteAddr)

						//Parse IP and port
						host, port, err := net.SplitHostPort(remoteAddr)
						if err != nil {
							t.Fatalf("Failed to parse remote address: %v", err)
						}

						//Expected IP and port
						expectedIP := localIP
						expectedPort := strconv.Itoa(int(htons(testPort)))

						if host != expectedIP || port != expectedPort {
							t.Fatalf("Expected redirected to %s:%s, but got %s:%s", expectedIP, expectedPort, host, port)
						}
					}},
				{
					name: "BPF_CGROUP_SOCK_CONNECT6_service_no_waypoint_lb_random_handle",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect6_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_netns_cookie
						localIP := get_local_ipv6(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := "[" + localIP + "]" + ":" + strconv.Itoa(serverPort)
						var testPort1 uint16 = 55555
						testIpPort1 := "[" + localIP + "]" + ":" + strconv.Itoa(int(htons(testPort1)))
						testListener1, err := net.Listen("tcp6", testIpPort1)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener1.Close()
						var testPort2 uint16 = 55556
						testIpPort2 := "[" + localIP + "]" + ":" + strconv.Itoa(int(htons(testPort2)))
						testListener2, err := net.Listen("tcp6", testIpPort2)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener2.Close()

						// record_kmesh_managed_ip
						enableAddr := "[" + constants.ControlCommandIp6 + "]" + ":" + strconv.Itoa(int(constants.OperEnableControl))
						(&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp6", enableAddr)

						//frontend map
						type ip_addr struct {
							Raw [16]byte
						}
						type frontend_key struct {
							Addr ip_addr
						}
						type frontend_value struct {
							UpstreamID uint32
						}
						FrontendMap := coll.Maps["km_frontend"]
						var f_key frontend_key

						ip6 := net.ParseIP(localIP).To16()
						if ip6 == nil {
							t.Fatalf("invalid IPv6 address")
						}
						copy(f_key.Addr.Raw[:], ip6)
						//value
						f_val := frontend_value{
							UpstreamID: 1,
						}
						if err := FrontendMap.Update(&f_key, &f_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//service map
						ServiceMap := coll.Maps["km_service"]
						const MAX_SERVICE_COUNT = 10
						type service_key struct {
							ServiceID uint32
						}
						type service_value struct {
							PrioEndpointCount [7]uint32
							LbPolicy          uint32
							ServicePort       [10]uint32
							TargetPort        [10]uint32
							WpAddr            ip_addr
							WaypointPort      uint32
						}
						//key
						s_key := service_key{
							ServiceID: 1,
						}
						wpIP := net.ParseIP(localIP).To16()
						s_val := service_value{
							LbPolicy: 0,
							PrioEndpointCount: [7]uint32{
								2, 0, 0, 0, 0, 0, 0,
							},
							ServicePort: [10]uint32{
								uint32(htons(uint16(serverPort))), 0, 0, 0, 0, 0, 0, 0, 0, 0,
							},
							TargetPort: [10]uint32{
								uint32(testPort2),
							},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: 0,
						}
						// WpAddr
						copy(s_val.WpAddr.Raw[:], wpIP)
						if err := ServiceMap.Update(&s_key, &s_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//endpoint
						type endpoint_key struct {
							service_id    uint32
							prio          uint32
							backend_index uint32 //rand_k
						}
						type endpoint_value struct {
							backend_uid uint32
						}
						//1
						e_key := endpoint_key{
							service_id:    1,
							prio:          0,
							backend_index: 1,
						}
						e_val := endpoint_value{
							backend_uid: 2,
						}
						EndpointMap := coll.Maps["km_endpoint"]
						if err := EndpointMap.Update(&e_key, &e_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}
						//2
						e_key = endpoint_key{
							service_id:    1,
							prio:          0,
							backend_index: 2,
						}
						e_val = endpoint_value{
							backend_uid: 6,
						}
						if err := EndpointMap.Update(&e_key, &e_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//backend
						BackendMap := coll.Maps["km_backend"]
						type backend_key struct {
							BackendUID uint32
						}

						type backend_value struct {
							Addr         ip_addr
							ServiceCount uint32
							Service      [MAX_SERVICE_COUNT]uint32
							WpAddr       ip_addr
							WaypointPort uint32
						}
						//1
						b_key := backend_key{
							BackendUID: 2,
						}
						wpIP = net.ParseIP(localIP).To16()
						b_val := backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: uint32(testPort1),
						}
						copy(b_val.WpAddr.Raw[:], wpIP)
						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}
						//2
						b_key = backend_key{
							BackendUID: 6,
						}
						IP := net.ParseIP(localIP).To16()
						b_val = backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: 0,
						}
						copy(b_val.Addr.Raw[:], IP)
						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						listener, err := net.Listen("tcp6", serverSocket)
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
						}).Dial("tcp6", serverSocket)
						if err != nil {
							t.Fatalf("Dial failed: %v", err)
						}
						defer conn.Close()
						//test
						remoteAddr := conn.RemoteAddr().String()
						t.Logf("Actual connected to: %s", remoteAddr)
						host, port, err := net.SplitHostPort(remoteAddr)
						if err != nil {
							t.Fatalf("Failed to parse remote address: %v", err)
						}
						t.Logf("Host: %s, Port: %s", host, port)
					}},
				{
					name: "BPF_CGROUP_SOCK_CONNECT6_service_no_waypoint_lb_locality_strict_handle",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect4_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_netns_cookie
						localIP := get_local_ipv6(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := "[" + localIP + "]" + ":" + strconv.Itoa(serverPort)
						var testPort1 uint16 = 55555
						testIpPort1 := "[" + localIP + "]" + ":" + strconv.Itoa(int(htons(testPort1)))
						testListener1, err := net.Listen("tcp6", testIpPort1)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener1.Close()
						var testPort2 uint16 = 55556
						testIpPort2 := "[" + localIP + "]" + ":" + strconv.Itoa(int(htons(testPort2)))
						testListener2, err := net.Listen("tcp6", testIpPort2)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener2.Close()

						// record_kmesh_managed_ip
						enableAddr := "[" + constants.ControlCommandIp6 + "]" + ":" + strconv.Itoa(int(constants.OperEnableControl))
						(&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp6", enableAddr)

						//frontend map
						type ip_addr struct {
							Raw [16]byte
						}
						type frontend_key struct {
							Addr ip_addr
						}
						type frontend_value struct {
							UpstreamID uint32
						}
						FrontendMap := coll.Maps["km_frontend"]
						var f_key frontend_key

						ip6 := net.ParseIP(localIP).To16()
						if ip6 == nil {
							t.Fatalf("invalid IPv6 address")
						}
						copy(f_key.Addr.Raw[:], ip6)
						//value
						f_val := frontend_value{
							UpstreamID: 1,
						}
						if err := FrontendMap.Update(&f_key, &f_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//service map
						ServiceMap := coll.Maps["km_service"]
						const MAX_SERVICE_COUNT = 10
						type service_key struct {
							ServiceID uint32
						}
						type service_value struct {
							PrioEndpointCount [7]uint32
							LbPolicy          uint32
							ServicePort       [10]uint32
							TargetPort        [10]uint32
							WpAddr            ip_addr
							WaypointPort      uint32
						}
						//key
						s_key := service_key{
							ServiceID: 1,
						}
						wpIP := net.ParseIP(localIP).To16()
						s_val := service_value{
							LbPolicy: 0,
							PrioEndpointCount: [7]uint32{
								2, 0, 0, 0, 0, 0, 0,
							},
							ServicePort: [10]uint32{
								uint32(htons(uint16(serverPort))), 0, 0, 0, 0, 0, 0, 0, 0, 0,
							},
							TargetPort: [10]uint32{
								uint32(testPort2),
							},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: 0,
						}
						// WpAddr
						copy(s_val.WpAddr.Raw[:], wpIP)
						if err := ServiceMap.Update(&s_key, &s_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//endpoint
						type endpoint_key struct {
							service_id    uint32
							backend_index uint32 //rand_k
							prio          uint32
						}
						type endpoint_value struct {
							backend_uid uint32
						}
						//1
						e_key := endpoint_key{
							service_id:    1,
							backend_index: 1,
							prio:          0,
						}
						e_val := endpoint_value{
							backend_uid: 2,
						}
						EndpointMap := coll.Maps["km_endpoint"]
						if err := EndpointMap.Update(&e_key, &e_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}
						//2
						e_key = endpoint_key{
							service_id:    1,
							backend_index: 2,
							prio:          0,
						}
						e_val = endpoint_value{
							backend_uid: 6,
						}
						if err := EndpointMap.Update(&e_key, &e_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//backend
						BackendMap := coll.Maps["km_backend"]
						type backend_key struct {
							BackendUID uint32
						}

						type backend_value struct {
							Addr         ip_addr
							ServiceCount uint32
							Service      [MAX_SERVICE_COUNT]uint32
							WpAddr       ip_addr
							WaypointPort uint32
						}
						//1
						b_key := backend_key{
							BackendUID: 2,
						}
						wpIP = net.ParseIP(localIP).To16()
						b_val := backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: uint32(testPort1),
						}
						copy(b_val.WpAddr.Raw[:], wpIP)
						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}
						//2
						b_key = backend_key{
							BackendUID: 6,
						}
						IP := net.ParseIP(localIP).To16()
						b_val = backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: 0,
						}
						copy(b_val.Addr.Raw[:], IP)
						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						listener, err := net.Listen("tcp6", serverSocket)
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
						}).Dial("tcp6", serverSocket)
						if err != nil {
							t.Fatalf("Dial failed: %v", err)
						}
						defer conn.Close()
						//test
						remoteAddr := conn.RemoteAddr().String()
						t.Logf("Actual connected to: %s", remoteAddr)
						host, port, err := net.SplitHostPort(remoteAddr)
						if err != nil {
							t.Fatalf("Failed to parse remote address: %v", err)
						}
						t.Logf("Host: %s, Port: %s", host, port)
					}},
				{
					name: "BPF_CGROUP_SOCK_CONNECT6_service_no_waypoint_lb_locality_failover_handle",
					workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
						// mount cgroup2
						mount_cgroup2(t, cgroupPath)
						defer syscall.Unmount(cgroupPath, 0)
						//load the eBPF program
						coll, lk := load_bpf_prog_to_cgroup(t, objFilePath, "cgroup_connect4_prog", cgroupPath)
						defer coll.Close()
						defer lk.Close()
						// Set the BPF configuration
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel:  constants.BPF_LOG_DEBUG,
							AuthzOffload: constants.DISABLED,
						})
						startLogReader(coll)

						// record_kmesh_managed_netns_cookie
						localIP := get_local_ipv6(t)
						clientPort := 12345
						serverPort := 54321
						serverSocket := "[" + localIP + "]" + ":" + strconv.Itoa(serverPort)
						var testPort1 uint16 = 55555
						testIpPort1 := "[" + localIP + "]" + ":" + strconv.Itoa(int(htons(testPort1)))
						testListener1, err := net.Listen("tcp6", testIpPort1)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener1.Close()
						var testPort2 uint16 = 55556
						testIpPort2 := "[" + localIP + "]" + ":" + strconv.Itoa(int(htons(testPort2)))
						testListener2, err := net.Listen("tcp6", testIpPort2)
						if err != nil {
							t.Fatalf("Failed to listen on testIpPort: %v", err)
						}
						defer testListener2.Close()

						// record_kmesh_managed_ip
						enableAddr := "[" + constants.ControlCommandIp6 + "]" + ":" + strconv.Itoa(int(constants.OperEnableControl))
						(&net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(localIP),
								Port: clientPort,
							},
							Timeout: 2 * time.Second,
						}).Dial("tcp6", enableAddr)

						//frontend map
						type ip_addr struct {
							Raw [16]byte
						}
						type frontend_key struct {
							Addr ip_addr
						}
						type frontend_value struct {
							UpstreamID uint32
						}
						FrontendMap := coll.Maps["km_frontend"]
						var f_key frontend_key

						ip6 := net.ParseIP(localIP).To16()
						if ip6 == nil {
							t.Fatalf("invalid IPv6 address")
						}
						copy(f_key.Addr.Raw[:], ip6)
						//value
						f_val := frontend_value{
							UpstreamID: 1,
						}
						if err := FrontendMap.Update(&f_key, &f_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//service map
						ServiceMap := coll.Maps["km_service"]
						const MAX_SERVICE_COUNT = 10
						type service_key struct {
							ServiceID uint32
						}
						type service_value struct {
							PrioEndpointCount [7]uint32
							LbPolicy          uint32
							ServicePort       [10]uint32
							TargetPort        [10]uint32
							WpAddr            ip_addr
							WaypointPort      uint32
						}
						//key
						s_key := service_key{
							ServiceID: 1,
						}
						wpIP := net.ParseIP(localIP).To16()
						s_val := service_value{
							LbPolicy: 0,
							PrioEndpointCount: [7]uint32{
								0, 0, 0, 0, 0, 2, 0,
							},
							ServicePort: [10]uint32{
								uint32(htons(uint16(serverPort))), 0, 0, 0, 0, 0, 0, 0, 0, 0,
							},
							TargetPort: [10]uint32{
								uint32(testPort2),
							},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: 0,
						}
						// WpAddr
						copy(s_val.WpAddr.Raw[:], wpIP)
						if err := ServiceMap.Update(&s_key, &s_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//endpoint
						type endpoint_key struct {
							service_id    uint32
							prio          uint32
							backend_index uint32 //rand_k
						}
						type endpoint_value struct {
							backend_uid uint32
						}
						//1
						e_key := endpoint_key{
							service_id:    1,
							prio:          5,
							backend_index: 1,
						}
						e_val := endpoint_value{
							backend_uid: 2,
						}
						EndpointMap := coll.Maps["km_endpoint"]
						if err := EndpointMap.Update(&e_key, &e_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}
						//2
						e_key = endpoint_key{
							service_id:    1,
							prio:          5,
							backend_index: 2,
						}
						e_val = endpoint_value{
							backend_uid: 6,
						}
						if err := EndpointMap.Update(&e_key, &e_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						//backend
						BackendMap := coll.Maps["km_backend"]
						type backend_key struct {
							BackendUID uint32
						}

						type backend_value struct {
							Addr         ip_addr
							ServiceCount uint32
							Service      [MAX_SERVICE_COUNT]uint32
							WpAddr       ip_addr
							WaypointPort uint32
						}
						//1
						b_key := backend_key{
							BackendUID: 2,
						}
						wpIP = net.ParseIP(localIP).To16()
						b_val := backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: uint32(testPort1),
						}
						copy(b_val.WpAddr.Raw[:], wpIP)
						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}
						//2
						b_key = backend_key{
							BackendUID: 6,
						}
						IP := net.ParseIP(localIP).To16()
						b_val = backend_value{
							Addr:         ip_addr{Raw: [16]byte{}},
							ServiceCount: 0,
							Service:      [MAX_SERVICE_COUNT]uint32{},
							WpAddr:       ip_addr{Raw: [16]byte{}},
							WaypointPort: 0,
						}
						copy(b_val.Addr.Raw[:], IP)
						if err := BackendMap.Update(&b_key, &b_val, ebpf.UpdateAny); err != nil {
							log.Fatalf("Update failed: %v", err)
						}

						listener, err := net.Listen("tcp6", serverSocket)
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
						}).Dial("tcp6", serverSocket)
						if err != nil {
							t.Fatalf("Dial failed: %v", err)
						}
						defer conn.Close()
						//test
						remoteAddr := conn.RemoteAddr().String()
						t.Logf("Actual connected to: %s", remoteAddr)
						host, port, err := net.SplitHostPort(remoteAddr)
						if err != nil {
							t.Fatalf("Failed to parse remote address: %v", err)
						}
						t.Logf("Host: %s, Port: %s", host, port)
					}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.objFilename, tt.run())
	}
}
