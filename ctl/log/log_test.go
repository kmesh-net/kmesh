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

package logs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kmesh.net/kmesh/ctl/utils"
)

func Test_GetJson_TimesOutOnStalledServer(t *testing.T) {
	unblock := make(chan struct{})
	defer close(unblock)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-unblock
	}))
	defer server.Close()

	original := utils.AdminRequestTimeout
	utils.AdminRequestTimeout = 50 * time.Millisecond
	defer func() { utils.AdminRequestTimeout = original }()

	var loggerNames []string
	start := time.Now()
	err := GetJson(server.URL, &loggerNames)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected GetJson against a stalled server to return an error, got nil")
	}
	if !strings.Contains(err.Error(), server.URL) {
		t.Errorf("error %q does not identify the request URL %q", err.Error(), server.URL)
	}
	if elapsed > 5*time.Second {
		t.Errorf("GetJson took %v to fail, expected it to be bounded by the configured timeout", elapsed)
	}
}
