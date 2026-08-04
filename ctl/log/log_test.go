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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSetLoggerLevelNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "logger nosuch does not exist")
	}))
	defer srv.Close()

	err := SetLoggerLevel(srv.URL, "nosuch:debug")
	if err == nil {
		t.Fatal("expected error when server returns non-OK status, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error %q should mention status code 400", err)
	}
}

func TestSetLoggerLevelOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "set logger success")
	}))
	defer srv.Close()

	err := SetLoggerLevel(srv.URL, "default:debug")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetLoggerLevelInvalidFlag(t *testing.T) {
	err := SetLoggerLevel("http://example.com", "nodebug")
	if err == nil {
		t.Fatal("expected error for invalid set flag")
	}
}
