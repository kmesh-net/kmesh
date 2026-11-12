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

package monitoring

import (
	"testing"
)

func TestGetKmeshDaemonPod(t *testing.T) {
	tests := []struct {
		args     []string
		wantPod  string
		wantBool bool
	}{
		{nil, "", false},
		{[]string{}, "", false},
		{[]string{"kmesh-daemon-abc"}, "kmesh-daemon-abc", true},
		{[]string{"--accesslog"}, "", false},
		{[]string{"some--thing"}, "some--thing", true},
		{[]string{"mypod"}, "mypod", true},
	}
	for _, tt := range tests {
		pod, ok := getKmeshDaemonPod(tt.args)
		if pod != tt.wantPod || ok != tt.wantBool {
			t.Errorf("getKmeshDaemonPod(%v) = (%q, %v), want (%q, %v)",
				tt.args, pod, ok, tt.wantPod, tt.wantBool)
		}
	}
}

func TestNewCmd(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "monitoring" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "monitoring")
	}
	for _, name := range []string{"accesslog", "all", "workloadMetrics", "connectionMetrics"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("--%s flag not defined", name)
		}
	}
}

func TestControlMonitoring_NoParameters(t *testing.T) {
	cmd := NewCmd()
	err := ControlMonitoring(cmd, []string{})
	if err == nil {
		t.Fatal("expected error when no flags are set, got nil")
	}
	expected := "no parameters. Need --accesslog, --workloadMetrics, --connectionMetrics or --all"
	if err.Error() != expected {
		t.Errorf("got error %q, want %q", err.Error(), expected)
	}
}

func TestControlMonitoring_InvalidFlagValue(t *testing.T) {
	testCases := []struct {
		name     string
		flagName string
		val      string
	}{
		{"invalid accesslog", "accesslog", "invalid"},
		{"invalid all", "all", "yes"},
		{"invalid workloadMetrics", "workloadMetrics", "true"},
		{"invalid connectionMetrics", "connectionMetrics", "1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewCmd()
			if err := cmd.Flags().Set(tc.flagName, tc.val); err != nil {
				t.Fatalf("failed to set flag: %v", err)
			}
			err := ControlMonitoring(cmd, []string{})
			if err == nil {
				t.Fatalf("expected error for %s=%s, got nil", tc.flagName, tc.val)
			}
			expected := "argument must be 'enable' or 'disable'"
			if err.Error() != expected {
				t.Errorf("got error %q, want %q", err.Error(), expected)
			}
		})
	}
}

func TestSetObservabilityPerKmeshDaemon_InvalidValue(t *testing.T) {
	err := SetObservabilityPerKmeshDaemon(nil, "kmesh-daemon-test", "invalid", MONITORING, patternMonitoring)
	if err == nil {
		t.Fatal("expected error for invalid value, got nil")
	}
	expected := "argument must be 'enable' or 'disable'"
	if err.Error() != expected {
		t.Errorf("got error %q, want %q", err.Error(), expected)
	}
}
