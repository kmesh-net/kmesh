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

package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewCmd(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "authz" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "authz")
	}

	got := map[string]bool{}
	for _, sub := range cmd.Commands() {
		got[sub.Name()] = true
	}
	for _, want := range []string{"enable", "disable", "status"} {
		if !got[want] {
			t.Errorf("subcommand %q not registered", want)
		}
	}
}

func TestNewEnableCmd(t *testing.T) {
	cmd := NewEnableCmd()
	if cmd.Use != "enable [podNames...]" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "enable [podNames...]")
	}
}

func TestNewDisableCmd(t *testing.T) {
	cmd := NewDisableCmd()
	if cmd.Use != "disable [podNames...]" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "disable [podNames...]")
	}
}

func TestNewStatusCmd(t *testing.T) {
	cmd := NewStatusCmd()
	if cmd.Use != "status [podNames...]" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "status [podNames...]")
	}
}

func TestSetAuthz(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Method = %q, want %q", r.Method, http.MethodPost)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	if err := SetAuthz(ts.URL); err != nil {
		t.Errorf("SetAuthz() failed: %v", err)
	}
}

func TestGetAuthzStatus(t *testing.T) {
	want := "enabled"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Method = %q, want %q", r.Method, http.MethodGet)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(want))
	}))
	defer ts.Close()

	got, err := GetAuthzStatus(ts.URL)
	if err != nil {
		t.Errorf("GetAuthzStatus() failed: %v", err)
	}
	if got != want {
		t.Errorf("GetAuthzStatus() = %q, want %q", got, want)
	}
}
