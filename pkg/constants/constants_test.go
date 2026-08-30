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

func TestModes(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"KernelNativeMode", KernelNativeMode, "kernel-native"},
		{"DualEngineMode", DualEngineMode, "dual-engine"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestDataPlaneLabels(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"DataPlaneModeLabel", DataPlaneModeLabel, "istio.io/dataplane-mode"},
		{"DataPlaneModeKmesh", DataPlaneModeKmesh, "kmesh"},
		{"KmeshRedirectionAnnotation", KmeshRedirectionAnnotation, "kmesh.net/redirection"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestXDPAndEncryption(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"XDP_PROG_NAME", XDP_PROG_NAME, "xdp_authz"},
		{"TC_MARK_DECRYPT", TC_MARK_DECRYPT, "tc_mark_decrypt"},
		{"TC_MARK_ENCRYPT", TC_MARK_ENCRYPT, "tc_mark_encrypt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestXfrmMarks(t *testing.T) {
	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"XfrmDecryptedMark", XfrmDecryptedMark, 0x00d0},
		{"XfrmEncryptMark", XfrmEncryptMark, 0x00e0},
		{"XfrmMarkMask", XfrmMarkMask, 0xffffffff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %#x, want %#x", tt.got, tt.want)
			}
		})
	}
}

func TestTCCommands(t *testing.T) {
	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"TC_ATTACH", TC_ATTACH, 0},
		{"TC_DETACH", TC_DETACH, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %d, want %d", tt.got, tt.want)
			}
		})
	}
}

func TestEnableDisable(t *testing.T) {
	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"ENABLED", ENABLED, 1},
		{"DISABLED", DISABLED, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %d, want %d", tt.got, tt.want)
			}
		})
	}
}

func TestBPFLogLevels(t *testing.T) {
	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"BPF_LOG_ERR", BPF_LOG_ERR, 0},
		{"BPF_LOG_WARN", BPF_LOG_WARN, 1},
		{"BPF_LOG_INFO", BPF_LOG_INFO, 2},
		{"BPF_LOG_DEBUG", BPF_LOG_DEBUG, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %d, want %d", tt.got, tt.want)
			}
		})
	}
}

func TestIPFamilies(t *testing.T) {
	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"MSG_TYPE_IPV4", MSG_TYPE_IPV4, 0},
		{"MSG_TYPE_IPV6", MSG_TYPE_IPV6, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %d, want %d", tt.got, tt.want)
			}
		})
	}
}

func TestControlCommands(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"ControlCommandIp4", ControlCommandIp4, "0.0.0.2"},
		{"ControlCommandIp6", ControlCommandIp6, "::2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestControlOperCodes(t *testing.T) {
	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"OperEnableControl", OperEnableControl, 929},
		{"OperDisableControl", OperDisableControl, 930},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %d, want %d", tt.got, tt.want)
			}
		})
	}
}

func TestTailCallIndices(t *testing.T) {
	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"TailCallConnect4Index", TailCallConnect4Index, 0},
		{"TailCallConnect6Index", TailCallConnect6Index, 1},
		{"TailCallPoliciesCheck", TailCallPoliciesCheck, 0},
		{"TailCallPolicyCheck", TailCallPolicyCheck, 1},
		{"TailCallAuthInUserSpace", TailCallAuthInUserSpace, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %d, want %d", tt.got, tt.want)
			}
		})
	}
}

func TestDirection(t *testing.T) {
	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"INBOUND", INBOUND, 1},
		{"OUTBOUND", OUTBOUND, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %d, want %d", tt.got, tt.want)
			}
		})
	}
}

func TestPaths(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"RootCertPath", RootCertPath, "/var/run/secrets/istio/root-cert.pem"},
		{"TrustDomain", TrustDomain, "cluster.local"},
		{"Cgroup2Path", Cgroup2Path, "/mnt/kmesh_cgroup2"},
		{"BpfFsPath", BpfFsPath, "/sys/fs/bpf"},
		{"VersionPath", VersionPath, "/bpf_kmesh/map/"},
		{"WorkloadVersionPath", WorkloadVersionPath, "/bpf_kmesh_workload/map/"},
		{"KmKernelNativeBpfPath", KmKernelNativeBpfPath, "/bpf_kmesh"},
		{"KmDualEngineBpfPath", KmDualEngineBpfPath, "/bpf_kmesh_workload"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestMapAndProgNames(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"TailCallMap", TailCallMap, "tail_call_map"},
		{"XDPTailCallMap", XDPTailCallMap, "km_xdp_tailcall"},
		{"Prog_link", Prog_link, "prog_link"},
		{"ALL_CIDR", ALL_CIDR, "0.0.0.0/0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}
