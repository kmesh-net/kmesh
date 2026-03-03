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
