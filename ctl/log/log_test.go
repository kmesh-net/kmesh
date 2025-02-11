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
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

const (
	testLoggerName  = "default"
	testLoggerLevel = "debug"
)

func TestLoggerEndToEnd(t *testing.T) {
	// Mock HTTP server for Kmesh daemon pod
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case patternLoggers:
			if r.Method == http.MethodGet {
				if r.URL.Query().Get("name") == "" {
					// Get all logger names
					loggerNames := []string{testLoggerName, "anotherLogger"}
					json.NewEncoder(w).Encode(loggerNames)
				} else {
					// Get specific logger level
					loggerInfo := LoggerInfo{
						Name:  testLoggerName,
						Level: testLoggerLevel,
					}
					json.NewEncoder(w).Encode(loggerInfo)
				}
			} else if r.Method == http.MethodPost {
				// Set logger level
				var loggerInfo LoggerInfo
				json.NewDecoder(r.Body).Decode(&loggerInfo)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Logger level updated successfully"))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Mock Kubernetes port forwarding
	utils.CreateKubeClient = func() (interface{}, error) {
		return nil, nil
	}
	utils.CreateKmeshPortForwarder = func(cli interface{}, podName string) (utils.PortForwarder, error) {
		return &mockPortForwarder{address: server.URL}, nil
	}

	// Test cases
	t.Run("Get all loggers", func(t *testing.T) {
		output := captureOutput(func() {
			cmd := NewCmd()
			cmd.SetArgs([]string{"test-pod"})
			cmd.Execute()
		})
		assert.Contains(t, output, "Existing Loggers")
		assert.Contains(t, output, testLoggerName)
	})

	t.Run("Get logger level", func(t *testing.T) {
		output := captureOutput(func() {
			cmd := NewCmd()
			cmd.SetArgs([]string{"test-pod", testLoggerName})
			cmd.Execute()
		})
		assert.Contains(t, output, fmt.Sprintf("Logger Name: %s", testLoggerName))
		assert.Contains(t, output, fmt.Sprintf("Logger Level: %s", testLoggerLevel))
	})

	t.Run("Set logger level", func(t *testing.T) {
		output := captureOutput(func() {
			cmd := NewCmd()
			cmd.SetArgs([]string{"test-pod", "--set", fmt.Sprintf("%s:%s", testLoggerName, testLoggerLevel)})
			cmd.Execute()
		})
		assert.Contains(t, output, "Logger level updated successfully")
	})

	t.Run("Invalid set flag", func(t *testing.T) {
		output := captureOutput(func() {
			cmd := NewCmd()
			cmd.SetArgs([]string{"test-pod", "--set", "invalid"})
			cmd.Execute()
		})
		assert.Contains(t, output, "Invalid set flag")
	})
}

// Helper function to capture CLI output
func captureOutput(f func()) string {
	var buf bytes.Buffer
	old := os.Stdout
	os.Stdout = &buf
	f()
	os.Stdout = old
	return buf.String()
}

// Mock PortForwarder
type mockPortForwarder struct {
	address string
}

func (m *mockPortForwarder) Start() error {
	return nil
}

func (m *mockPortForwarder) Close() {
}

func (m *mockPortForwarder) Address() string {
	return m.address
}
