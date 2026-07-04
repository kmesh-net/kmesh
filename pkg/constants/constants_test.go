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

import "testing"

func TestDataPlaneModeValues(t *testing.T) {
	if KernelNativeMode != "kernel-native" {
		t.Errorf("KernelNativeMode = %q, want %q", KernelNativeMode, "kernel-native")
	}
	if DualEngineMode != "dual-engine" {
		t.Errorf("DualEngineMode = %q, want %q", DualEngineMode, "dual-engine")
	}
}

func TestDataPlaneLabels(t *testing.T) {
	if DataPlaneModeLabel != "istio.io/dataplane-mode" {
		t.Errorf("DataPlaneModeLabel = %q, want %q", DataPlaneModeLabel, "istio.io/dataplane-mode")
	}
	if DataPlaneModeKmesh != "kmesh" {
		t.Errorf("DataPlaneModeKmesh = %q, want %q", DataPlaneModeKmesh, "kmesh")
	}
	if KmeshRedirectionAnnotation != "kmesh.net/redirection" {
		t.Errorf("KmeshRedirectionAnnotation = %q, want %q", KmeshRedirectionAnnotation, "kmesh.net/redirection")
	}
}

func TestControlCommandIPs(t *testing.T) {
	if ControlCommandIp4 != "0.0.0.2" {
		t.Errorf("ControlCommandIp4 = %q, want %q", ControlCommandIp4, "0.0.0.2")
	}
	if ControlCommandIp6 != "::2" {
		t.Errorf("ControlCommandIp6 = %q, want %q", ControlCommandIp6, "::2")
	}
}

func TestOperCodes(t *testing.T) {
	if OperEnableControl != 929 {
		t.Errorf("OperEnableControl = %d, want 929", OperEnableControl)
	}
	if OperDisableControl != 930 {
		t.Errorf("OperDisableControl = %d, want 930", OperDisableControl)
	}
}

func TestBPFLogLevels(t *testing.T) {
	levels := map[string]int{
		"BPF_LOG_ERR":   BPF_LOG_ERR,
		"BPF_LOG_WARN":  BPF_LOG_WARN,
		"BPF_LOG_INFO":  BPF_LOG_INFO,
		"BPF_LOG_DEBUG": BPF_LOG_DEBUG,
	}
	expected := map[string]int{
		"BPF_LOG_ERR":   0,
		"BPF_LOG_WARN":  1,
		"BPF_LOG_INFO":  2,
		"BPF_LOG_DEBUG": 3,
	}
	for name, val := range levels {
		if val != expected[name] {
			t.Errorf("%s = %d, want %d", name, val, expected[name])
		}
	}
}

func TestIPFamilyConstants(t *testing.T) {
	if MSG_TYPE_IPV4 != uint32(0) {
		t.Errorf("MSG_TYPE_IPV4 = %d, want 0", MSG_TYPE_IPV4)
	}
	if MSG_TYPE_IPV6 != uint32(1) {
		t.Errorf("MSG_TYPE_IPV6 = %d, want 1", MSG_TYPE_IPV6)
	}
}

func TestTailCallIndices(t *testing.T) {
	if TailCallConnect4Index != 0 {
		t.Errorf("TailCallConnect4Index = %d, want 0", TailCallConnect4Index)
	}
	if TailCallConnect6Index != 1 {
		t.Errorf("TailCallConnect6Index = %d, want 1", TailCallConnect6Index)
	}
}

func TestEnabledDisabled(t *testing.T) {
	if ENABLED != uint32(1) {
		t.Errorf("ENABLED = %d, want 1", ENABLED)
	}
	if DISABLED != uint32(0) {
		t.Errorf("DISABLED = %d, want 0", DISABLED)
	}
}

func TestTrafficDirection(t *testing.T) {
	if INBOUND != uint32(1) {
		t.Errorf("INBOUND = %d, want 1", INBOUND)
	}
	if OUTBOUND != uint32(2) {
		t.Errorf("OUTBOUND = %d, want 2", OUTBOUND)
	}
}
