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

package dump

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewCmd(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "dump" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "dump")
	}

	if flag := cmd.Flags().Lookup("output"); flag == nil {
		t.Error("output flag not registered")
	}
}

func TestUint32ToIPStr(t *testing.T) {
	tests := []struct {
		ip   uint32
		want string
	}{
		{0x0100007f, "127.0.0.1"},
		{0x08080808, "8.8.8.8"},
		{0x00000000, "0.0.0.0"},
	}
	for _, tt := range tests {
		if got := uint32ToIPStr(tt.ip); got != tt.want {
			t.Errorf("uint32ToIPStr(%d) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

func TestGetConfigDump(t *testing.T) {
	want := `{"workloads": []}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(want))
	}))
	defer ts.Close()

	got, err := GetConfigDump(ts.URL)
	if err != nil {
		t.Errorf("GetConfigDump() failed: %v", err)
	}
	if string(got) != want {
		t.Errorf("GetConfigDump() = %q, want %q", string(got), want)
	}
}
