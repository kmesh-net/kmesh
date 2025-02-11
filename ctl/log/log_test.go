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
package logs_test

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "net/http/httptest"
    "os"
    "testing"

    "github.com/spf13/cobra"
    "kmesh.net/kmesh/ctl/utils"
)

func MockServer() *httptest.Server {
    return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch r.URL.Path {
        case "/debug/loggers":
            if r.Method == http.MethodGet {
                loggers := []string{"default", "custom"}
                json.NewEncoder(w).Encode(loggers)
            } else if r.Method == http.MethodPost {
                var loggerInfo LoggerInfo
                json.NewDecoder(r.Body).Decode(&loggerInfo)
                fmt.Fprintf(w, "Logger %s set to level %s", loggerInfo.Name, loggerInfo.Level)
            }
        default:
            http.NotFound(w, r)
        }
    }))
}

type LoggerInfo struct {
    Name  string `json:"name,omitempty"`
    Level string `json:"level,omitempty"`
}

func TestRunGetOrSetLoggerLevel(t *testing.T) {
	// Start a mock server.
    server := MockServer()
    defer server.Close()

    // Replace the Kmesh daemon URL with the mock server URL.
    originalAddress := utils.KmeshDaemonAddress
    utils.KmeshDaemonAddress = server.URL
    defer func() { utils.KmeshDaemonAddress = originalAddress }()

    // Test cases
    tests := []struct {
        name     string
        args     []string
        setFlag  string
        expected string
        wantErr  bool
    }{
        {
            name:     "Get logger names",
            args:     []string{"kmesh-daemon-pod"},
            expected: "Existing Loggers:\n\tdefault\n\tcustom\n",
            wantErr:  false,
        },
        {
            name:     "Set logger level",
            args:     []string{"kmesh-daemon-pod"},
            setFlag:  "default:debug",
            expected: "Logger default set to level debug",
            wantErr:  false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Capture stdout to check the output.
            old := os.Stdout
            r, w, _ := os.Pipe()
            os.Stdout = w

            // Run the command.
            cmd := &cobra.Command{}
            cmd.Flags().String("set", tt.setFlag, "")
            RunGetOrSetLoggerLevel(cmd, tt.args)

            // Restore stdout.
            w.Close()
            os.Stdout = old

            var buf bytes.Buffer
            buf.ReadFrom(r)

            // Check the output.
            if got := buf.String(); got != tt.expected && !tt.wantErr {
                t.Errorf("RunGetOrSetLoggerLevel() = %v, want %v", got, tt.expected)
            }
        })
    }
}
