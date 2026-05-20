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
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewCmd(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "monitoring" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "monitoring")
	}

	for _, flagName := range []string{"accesslog", "all", "workloadMetrics", "connectionMetrics"} {
		if flag := cmd.Flags().Lookup(flagName); flag == nil {
			t.Errorf("%s flag not registered", flagName)
		}
	}
}

func TestGetKmeshDaemonPod(t *testing.T) {
	tests := []struct {
		args    []string
		wantPod string
		wantHas bool
	}{
		{[]string{"pod1"}, "pod1", true},
		{[]string{"--accesslog", "enable"}, "", false},
		{[]string{}, "", false},
	}
	for _, tt := range tests {
		gotPod, gotHas := getKmeshDaemonPod(tt.args)
		if gotPod != tt.wantPod || gotHas != tt.wantHas {
			t.Errorf("getKmeshDaemonPod(%v) = (%q, %v), want (%q, %v)", tt.args, gotPod, gotHas, tt.wantPod, tt.wantHas)
		}
	}
}

func TestSetObservability(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Method = %q, want %q", r.Method, http.MethodPost)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	if err := SetObservability(ts.URL, ACCESSLOG); err != nil {
		t.Errorf("SetObservability() failed: %v", err)
	}
}

func TestSetObservabilityError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Kmesh monitoring is disable, cannot enable accesslog."))
	}))
	defer ts.Close()

	err := SetObservability(ts.URL, ACCESSLOG)
	if err == nil {
		t.Error("SetObservability() expected error, got nil")
	}
}
