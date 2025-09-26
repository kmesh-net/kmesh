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

const (
	KernelNativeMode = "kernel-native"
	DualEngineMode   = "dual-engine"

	// DataPlaneModeLabel is the label used to indicate the data plane mode
	DataPlaneModeLabel = "istio.io/dataplane-mode"
	// DataPlaneModeKmesh is the value of the label to indicate the data plane mode is kmesh
	DataPlaneModeKmesh = "kmesh"
	// This annotation is used to indicate traffic redirection settings specific to Kmesh
	KmeshRedirectionAnnotation = "kmesh.net/redirection"

	XDP_PROG_NAME = "xdp_authz"
	ENABLED       = uint32(1)
	DISABLED      = uint32(0)

	TC_MARK_DECRYPT   = "tc_mark_decrypt"
	TC_MARK_ENCRYPT   = "tc_mark_encrypt"
	XfrmDecryptedMark = 0x00d0
	XfrmEncryptMark   = 0x00e0
	XfrmMarkMask      = 0xffffffff

	TC_ATTACH = 0
	TC_DETACH = 1

	RootCertPath = "/var/run/secrets/istio/root-cert.pem"
	TrustDomain  = "cluster.local"

	BPF_LOG_ERR   = 0
	BPF_LOG_WARN  = 1
	BPF_LOG_INFO  = 2
	BPF_LOG_DEBUG = 3

	// IP family
	MSG_TYPE_IPV4 = uint32(0)
	MSG_TYPE_IPV6 = uint32(1)

	// Ip(0.0.0.2 | ::2) used for control command, e.g. KmeshControl | ByPass
	ControlCommandIp4 = "0.0.0.2"
	ControlCommandIp6 = "::2"
	// Oper code for control command
	OperEnableControl  = 929
	OperDisableControl = 930

	// tail call index in cgroup connect tail call prog map
	TailCallConnect4Index = 0
	TailCallConnect6Index = 1
	// tail call index in xdp tail call prog map
	TailCallPoliciesCheck   = 0
	TailCallPolicyCheck     = 1
	TailCallAuthInUserSpace = 2

	INBOUND  = uint32(1)
	OUTBOUND = uint32(2)

	Cgroup2Path = "/mnt/kmesh_cgroup2"
	BpfFsPath   = "/sys/fs/bpf"

	VersionPath         = "/bpf_kmesh/map/"
	WorkloadVersionPath = "/bpf_kmesh_workload/map/"

	KmKernelNativeBpfPath = "/bpf_kmesh"
	KmDualEngineBpfPath   = "/bpf_kmesh_workload"

	TailCallMap    = "tail_call_map"
	XDPTailCallMap = "km_xdp_tailcall"
	Prog_link      = "prog_link"

	ALL_CIDR = "0.0.0.0/0"

	MapSpecDir      = "/mnt/kmesh_mapspecs"
    MapSpecFilename = "mapspecs_by_pkg.json"
)
