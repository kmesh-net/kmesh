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
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testLoggerName  = "default"
	testLoggerLevel = "debug"
)

func TestLoggerEndToEnd(t *testing.T) {
	// Test cases
	t.Run("Get all loggers", func(t *testing.T) {
		// Run kmeshctl logs get command
		output, err := runKmeshctl("logs", "get")
		assert.NoError(t, err)

		// Verify the output contains the test logger name
		assert.Contains(t, output, testLoggerName)
	})

	t.Run("Get logger level", func(t *testing.T) {
		// Run kmeshctl logs get command for a specific logger
		output, err := runKmeshctl("logs", "get", testLoggerName)
		assert.NoError(t, err)

		// Verify the output contains the test logger name and level
		assert.Contains(t, output, fmt.Sprintf("Logger Name: %s", testLoggerName))
		assert.Contains(t, output, fmt.Sprintf("Logger Level: %s", testLoggerLevel))
	})

	t.Run("Set logger level", func(t *testing.T) {
		// Run kmeshctl logs set command to update the logger level
		output, err := runKmeshctl("logs", "set", testLoggerName, testLoggerLevel)
		assert.NoError(t, err)

		// Verify the output indicates success
		assert.Contains(t, output, "Logger level updated successfully")
	})

	t.Run("Invalid set flag", func(t *testing.T) {
		// Run kmeshctl logs set command with an invalid flag
		output, err := runKmeshctl("logs", "set", "invalid")
		assert.Error(t, err) // Expect an error for invalid input

		// Verify the output contains the error message
		assert.Contains(t, output, "Invalid set flag")
	})
}

// Helper function to run kmeshctl commands
func runKmeshctl(args ...string) (string, error) {
	cmd := exec.Command("kmeshctl", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
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
