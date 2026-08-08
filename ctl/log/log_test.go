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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer func() {
		os.Stdout = old
		_ = w.Close()
		_ = r.Close()
	}()

	os.Stdout = w
	fn()
	_ = w.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read captured stdout: %v", err)
	}
	return buf.String()
}

func TestGetJson(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		want := []string{"default", "controller", "bpf"}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(want)
		}))
		defer srv.Close()

		var got []string
		if err := GetJson(srv.URL, &got); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != len(want) {
			t.Fatalf("len = %d, want %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("non-200 status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		var v []string
		if err := GetJson(srv.URL, &v); err == nil {
			t.Fatal("expected error for 500 response")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("{bad"))
		}))
		defer srv.Close()

		var v []string
		err := GetJson(srv.URL, &v)
		if err == nil || !strings.Contains(err.Error(), "unmarshal") {
			t.Fatalf("expected unmarshal error, got: %v", err)
		}
	})

	t.Run("connection error", func(t *testing.T) {
		var v []string
		if err := GetJson("http://localhost:0/nope", &v); err == nil {
			t.Fatal("expected connection error")
		}
	})
}

func TestGetLoggerNames(t *testing.T) {
	names := []string{"default", "controller", "bpf"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(names)
	}))
	defer srv.Close()

	out := captureStdout(t, func() { GetLoggerNames(srv.URL) })
	for _, n := range names {
		if !strings.Contains(out, n) {
			t.Errorf("output missing logger %q", n)
		}
	}
}

func TestGetLoggerLevel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(LoggerInfo{Name: "default", Level: "info"})
	}))
	defer srv.Close()

	out := captureStdout(t, func() { GetLoggerLevel(srv.URL) })
	if !strings.Contains(out, "default") || !strings.Contains(out, "info") {
		t.Errorf("unexpected output: %s", out)
	}
}

func TestSetLoggerLevel(t *testing.T) {
	ch := make(chan LoggerInfo, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		var info LoggerInfo
		json.NewDecoder(r.Body).Decode(&info)
		ch <- info
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	captureStdout(t, func() { SetLoggerLevel(srv.URL, "default:debug") })

	got := <-ch
	if got.Name != "default" || got.Level != "debug" {
		t.Errorf("sent body = {%q, %q}, want {default, debug}", got.Name, got.Level)
	}
}

func TestNewCmd(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "log" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "log")
	}
	if cmd.Flags().Lookup("set") == nil {
		t.Fatal("--set flag not defined")
	}
}
