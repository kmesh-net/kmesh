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
	AdsMode      = "ads"
	WorkloadMode = "workload"

	// DataPlaneModeLabel is the label used to indicate the data plane mode
	DataPlaneModeLabel = "istio.io/dataplane-mode"
	// DataPlaneModeKmesh is the value of the label to indicate the data plane mode is kmesh
	DataPlaneModeKmesh = "kmesh"
	// This annotation is used to indicate traffic redirection settings specific to Kmesh
	KmeshRedirectionAnnotation = "kmesh.net/redirection"

	XDP_PROG_NAME = "xdp_shutdown"

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

	// tail call index in tail call prog map
	TailCallConnect4Index   = 0
	TailCallConnect6Index   = 1
	TailCallDstPortMatch    = 2
	TailCallSrcIPMatch      = 3
	TailCallDstIPMatch      = 4
	TailCallAuthInUserSpace = 5

	INBOUND  = uint32(1)
	OUTBOUND = uint32(2)

	Cgroup2Path = "/mnt/kmesh_cgroup2"
	BpfFsPath   = "/sys/fs/bpf"

	VersionPath         = "/bpf_kmesh/map/"
	WorkloadVersionPath = "/bpf_kmesh_workload/map/"
)
