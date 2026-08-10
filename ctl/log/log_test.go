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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// captureStdout intercepts stdout during the execution of f and returns the captured output.
func captureStdout(f func()) string {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		r.Close()
		outC <- buf.String()
	}()

	func() {
		defer func() {
			os.Stdout = oldStdout
			w.Close()
		}()
		os.Stdout = w
		f()
	}()

	return <-outC
}

func TestGetLoggerNames(t *testing.T) {
	tests := []struct {
		name           string
		mockStatus     int
		mockBody       string
		expectedStdout string
	}{
		{
			name:           "Retrieve all logger names",
			mockStatus:     http.StatusOK,
			mockBody:       `["default", "bpf"]`,
			expectedStdout: "Existing Loggers:\n\tdefault\n\tbpf\n",
		},
		{
			name:           "Server error",
			mockStatus:     http.StatusInternalServerError,
			mockBody:       `Internal Server Error`,
			expectedStdout: "", // Function logs an error internally, stdout stays empty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.mockStatus)
				w.Write([]byte(tt.mockBody))
			}))
			defer server.Close()

			output := captureStdout(func() {
				GetLoggerNames(server.URL)
			})

			if tt.expectedStdout != "" && !strings.Contains(output, tt.expectedStdout) {
				t.Errorf("expected stdout to contain %q, got %q", tt.expectedStdout, output)
			}
		})
	}
}

func TestGetLoggerLevel(t *testing.T) {
	tests := []struct {
		name           string
		mockStatus     int
		mockBody       string
		expectedStdout string
	}{
		{
			name:           "Retrieve specific logger level",
			mockStatus:     http.StatusOK,
			mockBody:       `{"name":"default","level":"debug"}`,
			expectedStdout: "Logger Name: default\nLogger Level: debug\n",
		},
		{
			name:           "Malformed JSON",
			mockStatus:     http.StatusOK,
			mockBody:       `{invalid`,
			expectedStdout: "", // Logs error, does not print
		},
		{
			name:           "Invalid logger name (404)",
			mockStatus:     http.StatusNotFound,
			mockBody:       `Not Found`,
			expectedStdout: "", // Logs error, does not print
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.mockStatus)
				w.Write([]byte(tt.mockBody))
			}))
			defer server.Close()

			output := captureStdout(func() {
				GetLoggerLevel(server.URL)
			})

			if tt.expectedStdout != "" && !strings.Contains(output, tt.expectedStdout) {
				t.Errorf("expected stdout to contain %q, got %q", tt.expectedStdout, output)
			}
		})
	}
}

func TestSetLoggerLevel(t *testing.T) {
	tests := []struct {
		name           string
		setFlag        string
		mockStatus     int
		mockBody       string
		expectedStdout string
	}{
		{
			name:           "Set logger level successfully",
			setFlag:        "default:debug",
			mockStatus:     http.StatusOK,
			mockBody:       "Logger level updated successfully",
			expectedStdout: "Logger level updated successfully\n",
		},
		{
			name:           "Invalid logger name returns error",
			setFlag:        "unknown:debug",
			mockStatus:     http.StatusNotFound,
			mockBody:       "Logger not found",
			expectedStdout: "Logger not found\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.mockStatus)
				w.Write([]byte(tt.mockBody))
			}))
			defer server.Close()

			output := captureStdout(func() {
				// We don't pass an invalid format like "invalid" because SetLoggerLevel would call os.Exit(1).
				// We pass correctly formatted string.
				SetLoggerLevel(server.URL, tt.setFlag)
			})

			if tt.expectedStdout != "" && !strings.Contains(output, tt.expectedStdout) {
				t.Errorf("expected stdout to contain %q, got %q", tt.expectedStdout, output)
			}
		})
	}
}
