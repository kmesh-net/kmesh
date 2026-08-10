//go:build integ
// +build integ

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

package kmesh

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/util/retry"
)

func TestLogCommand(t *testing.T) {
	framework.NewTest(t).
		Run(func(t framework.TestContext) {
			// Fetch Kmesh daemon pod using existing helper
			podName, _, err := getPodNameAndIP(t, KmeshNamespace, "kmesh")
			if err != nil || podName == "" {
				t.Fatalf("failed to fetch ready Kmesh daemon pod: %v", err)
			}

			// Test 1: Get all logger names
			t.NewSubTest("GetLoggerNames").Run(func(t framework.TestContext) {
				retry.UntilSuccessOrFail(t, func() error {
					cmd := exec.Command("kmeshctl", "log", podName)
					out, err := cmd.CombinedOutput()
					if err != nil {
						return fmt.Errorf("command failed: %v, output: %s", err, string(out))
					}
					output := string(out)
					if !strings.Contains(output, "Existing Loggers:") || !strings.Contains(output, "default") {
						return fmt.Errorf("expected output to contain logger names, got: %s", output)
					}
					return nil
				}, retry.Timeout(30*time.Second), retry.BackoffDelay(1*time.Second))
			})

			// Test 2: Get specific logger level
			t.NewSubTest("GetLoggerLevel").Run(func(t framework.TestContext) {
				retry.UntilSuccessOrFail(t, func() error {
					cmd := exec.Command("kmeshctl", "log", podName, "default")
					out, err := cmd.CombinedOutput()
					if err != nil {
						return fmt.Errorf("command failed: %v, output: %s", err, string(out))
					}
					output := string(out)
					if !strings.Contains(output, "Logger Name: default") || !strings.Contains(output, "Logger Level: ") {
						return fmt.Errorf("expected output to contain logger level, got: %s", output)
					}
					return nil
				}, retry.Timeout(30*time.Second), retry.BackoffDelay(1*time.Second))
			})

			// Test 3: Set specific logger level and verify
			t.NewSubTest("SetLoggerLevel").Run(func(t framework.TestContext) {
				var originalLevel string
				retry.UntilSuccessOrFail(t, func() error {
					cmd := exec.Command("kmeshctl", "log", podName, "default")
					out, err := cmd.CombinedOutput()
					if err != nil {
						return fmt.Errorf("command failed: %v, output: %s", err, string(out))
					}
					output := string(out)
					parts := strings.Split(output, "Logger Level: ")
					if len(parts) > 1 {
						originalLevel = strings.TrimSpace(strings.Split(parts[1], "\n")[0])
						return nil
					}
					return fmt.Errorf("could not extract original logger level from output: %s", output)
				}, retry.Timeout(30*time.Second), retry.BackoffDelay(1*time.Second))

				// Cleanup: restore original level after test
				defer func() {
					if originalLevel == "" {
						return
					}
					if err := exec.Command(
						"kmeshctl",
						"log",
						podName,
						"--set",
						"default:"+originalLevel,
					).Run(); err != nil {
						t.Logf("cleanup failed to restore original logger level (%s): %v", originalLevel, err)
					}
				}()

				retry.UntilSuccessOrFail(t, func() error {
					cmd := exec.Command("kmeshctl", "log", podName, "--set", "default:debug")
					out, err := cmd.CombinedOutput()
					if err != nil {
						return fmt.Errorf("command failed: %v, output: %s", err, string(out))
					}
					// Note: actual output depends on daemon response, typically empty or success message.
					// We check if it ran without errors.
					return nil
				}, retry.Timeout(30*time.Second), retry.BackoffDelay(1*time.Second))

				// Verify it was actually set
				retry.UntilSuccessOrFail(t, func() error {
					cmd := exec.Command("kmeshctl", "log", podName, "default")
					out, err := cmd.CombinedOutput()
					if err != nil {
						return fmt.Errorf("command failed: %v, output: %s", err, string(out))
					}
					output := string(out)
					if !strings.Contains(output, "Logger Level: debug") {
						return fmt.Errorf("expected logger level to be debug, got: %s", output)
					}
					return nil
				}, retry.Timeout(30*time.Second), retry.BackoffDelay(1*time.Second))
			})
		})
}
