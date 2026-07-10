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

package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func Test_NewAdminHTTPClient_UsesAdminRequestTimeout(t *testing.T) {
	client := NewAdminHTTPClient()
	if client.Timeout != AdminRequestTimeout {
		t.Errorf("client.Timeout = %v, want %v", client.Timeout, AdminRequestTimeout)
	}
}

func Test_NewAdminHTTPClient_TimesOutOnStalledServer(t *testing.T) {
	unblock := make(chan struct{})
	defer close(unblock)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-unblock
	}))
	defer server.Close()

	original := AdminRequestTimeout
	AdminRequestTimeout = 50 * time.Millisecond
	defer func() { AdminRequestTimeout = original }()

	client := NewAdminHTTPClient()
	start := time.Now()
	_, err := client.Get(server.URL)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected request against stalled server to fail with a timeout error, got nil error")
	}
	if elapsed > 5*time.Second {
		t.Errorf("request took %v to fail, expected it to be bounded by the configured timeout", elapsed)
	}
}
