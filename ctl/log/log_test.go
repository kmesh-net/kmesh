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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewCmd(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "log" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "log")
	}

	if flag := cmd.Flags().Lookup("set"); flag == nil {
		t.Error("set flag not registered")
	}
}

func TestGetJson(t *testing.T) {
	want := LoggerInfo{Name: "default", Level: "debug"}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(want)
	}))
	defer ts.Close()

	var got LoggerInfo
	if err := GetJson(ts.URL, &got); err != nil {
		t.Errorf("GetJson() failed: %v", err)
	}
	if got != want {
		t.Errorf("GetJson() = %+v, want %+v", got, want)
	}
}

func TestSetLoggerLevel(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Method = %q, want %q", r.Method, http.MethodPost)
		}
		var info LoggerInfo
		if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		if info.Name != "default" || info.Level != "debug" {
			t.Errorf("received info %+v, want {default debug}", info)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer ts.Close()

	resp, err := SetLoggerLevel(ts.URL, "default:debug")
	if err != nil {
		t.Errorf("SetLoggerLevel() failed: %v", err)
	}
	if resp != "success" {
		t.Errorf("SetLoggerLevel() = %q, want %q", resp, "success")
	}
}
