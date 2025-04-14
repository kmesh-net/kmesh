//go:build linux && (amd64 || arm64) && !aix && !ppc64

package bpftests

import (
	"testing"

	"github.com/cilium/ebpf"
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

const (
	xdpTailCallMap = "km_xdp_tailcall"
)

func testWorkload(t *testing.T) {
	t.Run("XDP", testXDP)
}

func testXDP(t *testing.T) {
	XDPtests := []unittest{
		{
			name:        "1_shutdown_in_userspace__should_shutdown",
			objFilename: "xdp_shutdown_in_userspace_test.o",
			setupInUserSpace: func(t *testing.T, coll *ebpf.Collection) {
				workload_xdp_registerTailCall(t, coll)
				setBpfConfig(t, coll, &factory.GlobalBpfConfig{
					BpfLogLevel:  constants.BPF_LOG_DEBUG,
					AuthzOffload: constants.DISABLED,
				})
			},
		},
		{
			name:        "2_shutdown_in_userspace__should_not_shutdown",
			objFilename: "xdp_shutdown_in_userspace_test.o",
			setupInUserSpace: func(t *testing.T, coll *ebpf.Collection) {
				workload_xdp_registerTailCall(t, coll)
				setBpfConfig(t, coll, &factory.GlobalBpfConfig{
					BpfLogLevel:  constants.BPF_LOG_DEBUG,
					AuthzOffload: constants.DISABLED,
				})
			},
		},
		{
			name:        "3_deny_policy_matched",
			objFilename: "xdp_authz_offload_test.o",
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
			name:        "4_allow_policy_matched",
			objFilename: "xdp_authz_offload_test.o",
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
	}

	for _, tt := range XDPtests {
		t.Run(tt.name, func(t *testing.T) {
			loadAndRunSpec(t, &tt)
		})
	}
}

// workload_xdp_registerTailCall registers the tail call for XDP programs.
func workload_xdp_registerTailCall(t *testing.T, coll *ebpf.Collection) {
	if coll == nil {
		t.Fatal("coll is nil")
	}
	registerTailCall(t, coll, xdpTailCallMap, constants.TailCallPoliciesCheck, "policies_check")
	registerTailCall(t, coll, xdpTailCallMap, constants.TailCallPolicyCheck, "policy_check")
	registerTailCall(t, coll, xdpTailCallMap, constants.TailCallAuthInUserSpace, "xdp_shutdown_in_userspace")
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
