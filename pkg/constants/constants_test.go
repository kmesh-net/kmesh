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

package constants

import (
	"testing"
)

func TestConstants(t *testing.T) {
	tests := []struct {
		name     string
		got      interface{}
		expected interface{}
	}{
		// Models
		{"KernelNativeMode", KernelNativeMode, "kernel-native"},
		{"DualEngineMode", DualEngineMode, "dual-engine"},

		// Labels and Annotations
		{"DataPlaneModeLabel", DataPlaneModeLabel, "istio.io/dataplane-mode"},
		{"DataPlaneModeKmesh", DataPlaneModeKmesh, "kmesh"},
		{"KmeshRedirectionAnnotation", KmeshRedirectionAnnotation, "kmesh.net/redirection"},

		// BPF and Networking
		{"XDP_PROG_NAME", XDP_PROG_NAME, "xdp_authz"},
		{"ENABLED", ENABLED, uint32(1)},
		{"DISABLED", DISABLED, uint32(0)},
		{"XfrmDecryptedMark", XfrmDecryptedMark, int(0x00d0)},
		{"XfrmEncryptMark", XfrmEncryptMark, int(0x00e0)},
		{"XfrmMarkMask", XfrmMarkMask, int(0xffffffff)},
		{"TC_MARK_DECRYPT", TC_MARK_DECRYPT, "tc_mark_decrypt"},
		{"TC_MARK_ENCRYPT", TC_MARK_ENCRYPT, "tc_mark_encrypt"},
		{"TC_ATTACH", TC_ATTACH, int(0)},
		{"TC_DETACH", TC_DETACH, int(1)},
		{"ALL_CIDR", ALL_CIDR, "0.0.0.0/0"},

		// Traffic Directions
		{"INBOUND", INBOUND, uint32(1)},
		{"OUTBOUND", OUTBOUND, uint32(2)},

		// IP Family
		{"MSG_TYPE_IPV4", MSG_TYPE_IPV4, uint32(0)},
		{"MSG_TYPE_IPV6", MSG_TYPE_IPV6, uint32(1)},

		// Paths
		{"RootCertPath", RootCertPath, "/var/run/secrets/istio/root-cert.pem"},
		{"Cgroup2Path", Cgroup2Path, "/mnt/kmesh_cgroup2"},
		{"BpfFsPath", BpfFsPath, "/sys/fs/bpf"},
		{"VersionPath", VersionPath, "/bpf_kmesh/map/"},
		{"WorkloadVersionPath", WorkloadVersionPath, "/bpf_kmesh_workload/map/"},
		{"KmKernelNativeBpfPath", KmKernelNativeBpfPath, "/bpf_kmesh"},
		{"KmDualEngineBpfPath", KmDualEngineBpfPath, "/bpf_kmesh_workload"},

		// Control Commands
		{"OperEnableControl", OperEnableControl, int(929)},
		{"OperDisableControl", OperDisableControl, int(930)},
		{"ControlCommandIp4", ControlCommandIp4, "0.0.0.2"},
		{"ControlCommandIp6", ControlCommandIp6, "::2"},

		// Tail Call Indices
		{"TailCallConnect4Index", TailCallConnect4Index, int(0)},
		{"TailCallConnect6Index", TailCallConnect6Index, int(1)},
		{"TailCallPoliciesCheck", TailCallPoliciesCheck, int(0)},
		{"TailCallPolicyCheck", TailCallPolicyCheck, int(1)},
		{"TailCallAuthInUserSpace", TailCallAuthInUserSpace, int(2)},

		// Maps and Progs
		{"TailCallMap", TailCallMap, "tail_call_map"},
		{"XDPTailCallMap", XDPTailCallMap, "km_xdp_tailcall"},
		{"Prog_link", Prog_link, "prog_link"},

		// Misc
		{"TrustDomain", TrustDomain, "cluster.local"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				// Using %#v to catch type mismatches in the CI logs
				t.Errorf("%s failed: expected %#v, got %#v", tt.name, tt.expected, tt.got)
			}
		})
	}
}

func TestLogConstants(t *testing.T) {
	if BPF_LOG_ERR != 0 || BPF_LOG_WARN != 1 || BPF_LOG_INFO != 2 || BPF_LOG_DEBUG != 3 {
		t.Errorf("BPF Log levels are incorrectly defined")
	}
}
