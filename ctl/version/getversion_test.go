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


package version

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kmesh.net/kmesh/pkg/version"
)

func TestGetVersion_ForwarderCreationError(t *testing.T) {
	fake := &fakeCLIClient{forwarderErr: errors.New("connection refused")}

	v := getVersion(fake, "some-pod")

	if v.GitVersion != "" {
		t.Errorf("expected empty GitVersion on forwarder creation error, got %q", v.GitVersion)
	}
}

func TestGetVersion_ForwarderStartError(t *testing.T) {
	fake := &fakeCLIClient{
		forwarder: &fakePortForwarder{startErr: errors.New("failed to start")},
	}

	v := getVersion(fake, "some-pod")

	if v.GitVersion != "" {
		t.Errorf("expected empty GitVersion on forwarder start error, got %q", v.GitVersion)
	}
}

func TestGetVersion_Success(t *testing.T) {
	want := version.Info{
		GitVersion: "v1.2.3",
		GitCommit:  "abc123",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer server.Close()

	// server.URL looks like "http://127.0.0.1:PORT" — Address() should return "host:port" only.
	address := strings.TrimPrefix(server.URL, "http://")

	fake := &fakeCLIClient{
		forwarder: &fakePortForwarder{address: address},
	}

	got := getVersion(fake, "some-pod")

	if got.GitVersion != want.GitVersion {
		t.Errorf("GitVersion = %q, want %q", got.GitVersion, want.GitVersion)
	}
	if got.GitCommit != want.GitCommit {
		t.Errorf("GitCommit = %q, want %q", got.GitCommit, want.GitCommit)
	}
}
