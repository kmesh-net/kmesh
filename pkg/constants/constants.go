/*
 * Copyright 2024 The Kmesh Authors.
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

	XDP_PROG_NAME = "xdp_shutdown"

	RootCertPath = "/var/run/secrets/istio/root-cert.pem"

	BPF_LOG_ERR   = 0
	BPF_LOG_WARN  = 1
	BPF_LOG_INFO  = 2
	BPF_LOG_DEBUG = 3

	// Ip(0.0.0.2 | ::2) used for control command, e.g. KmeshControl | ByPass
	ControlCommandIp4 = "0.0.0.2"
	ControlCommandIp6 = "::2"
	// Oper code for control command
	OperEnableControl  = 929
	OperDisableControl = 930
	OperEnableBypass   = 931
	OperDisableByPass  = 932

	// tail call index in tail call prog map
	TailCallConnect4Index = 0
	TailCallConnect6Index = 1
)
