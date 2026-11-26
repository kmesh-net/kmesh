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
	kubetest "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/util/retry"
)

// runKmeshctl runs `kmeshctl <args...>` against the local kmeshctl binary
// (installed onto PATH by test/e2e/run_test.sh) and returns its combined
// stdout/stderr output.
func runKmeshctl(t framework.TestContext, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("kmeshctl", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// getKmeshPodName returns the name of a Ready Kmesh daemon pod to target
// with `kmeshctl log`.
func getKmeshPodName(t framework.TestContext) string {
	t.Helper()
	pods, err := kubetest.CheckPodsAreReady(kubetest.NewPodFetch(t.AllClusters()[0], KmeshNamespace, "app=kmesh"))
	if err != nil {
		t.Fatalf("failed to find a ready Kmesh pod: %v", err)
	}
	if len(pods) == 0 {
		t.Fatal("no Kmesh pods found")
	}
	return pods[0].Name
}

// waitForLoggerLevel polls `kmeshctl log <pod> <logger>` until its reported
// level matches want, instead of sleeping a fixed duration.
func waitForLoggerLevel(t framework.TestContext, pod, logger, want string) {
	t.Helper()
	if err := retry.UntilSuccess(func() error {
		out, err := runKmeshctl(t, "log", pod, logger)
		if err != nil {
			return fmt.Errorf("kmeshctl log %s %s failed: %v, output: %s", pod, logger, err, out)
		}
		wantLine := fmt.Sprintf("Logger Level: %s", want)
		if !strings.Contains(out, wantLine) {
			return fmt.Errorf("logger %s level not yet %q, output: %s", logger, want, out)
		}
		return nil
	}, retry.Timeout(30*time.Second), retry.Delay(time.Second)); err != nil {
		t.Fatalf("logger %s never reached level %q: %v", logger, want, err)
	}
}

// TestKmeshctlLog exercises the `kmeshctl log` sub-command end to end
// against a real Kmesh daemon pod: listing logger names, reading a
// logger's level, setting a logger's level, and rejecting an invalid
// --set value.
func TestKmeshctlLog(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		pod := getKmeshPodName(t)

		t.NewSubTest("list logger names").Run(func(t framework.TestContext) {
			out, err := runKmeshctl(t, "log", pod)
			if err != nil {
				t.Fatalf("kmeshctl log %s failed: %v, output: %s", pod, err, out)
			}
			if !strings.Contains(out, "Existing Loggers:") {
				t.Fatalf("expected output to list existing loggers, got: %s", out)
			}
			if !strings.Contains(out, "default") {
				t.Fatalf("expected \"default\" logger to be listed, got: %s", out)
			}
		})

		t.NewSubTest("get default logger level").Run(func(t framework.TestContext) {
			out, err := runKmeshctl(t, "log", pod, "default")
			if err != nil {
				t.Fatalf("kmeshctl log %s default failed: %v, output: %s", pod, err, out)
			}
			if !strings.Contains(out, "Logger Name: default") {
				t.Fatalf("expected output to name the \"default\" logger, got: %s", out)
			}
			if !strings.Contains(out, "Logger Level:") {
				t.Fatalf("expected output to report a logger level, got: %s", out)
			}
		})

		t.NewSubTest("set and restore default logger level").Run(func(t framework.TestContext) {
			// Capture the current level so the change made by this test
			// doesn't leak into any other test that runs afterwards.
			before, err := runKmeshctl(t, "log", pod, "default")
			if err != nil {
				t.Fatalf("kmeshctl log %s default failed: %v, output: %s", pod, err, before)
			}
			originalLevel := "info"
			for _, line := range strings.Split(before, "\n") {
				if rest, found := strings.CutPrefix(line, "Logger Level: "); found {
					originalLevel = strings.TrimSpace(rest)
				}
			}
			t.Cleanup(func() {
				if out, err := runKmeshctl(t, "log", pod, "--set", "default:"+originalLevel); err != nil {
					t.Logf("failed to restore default logger level to %q: %v, output: %s", originalLevel, err, out)
				}
			})

			out, err := runKmeshctl(t, "log", pod, "--set", "default:debug")
			if err != nil {
				t.Fatalf("kmeshctl log %s --set default:debug failed: %v, output: %s", pod, err, out)
			}
			if !strings.Contains(out, "OK") {
				t.Fatalf("expected daemon to acknowledge the level change with \"OK\", got: %s", out)
			}

			waitForLoggerLevel(t, pod, "default", "debug")
		})

		t.NewSubTest("reject invalid --set value").Run(func(t framework.TestContext) {
			out, err := runKmeshctl(t, "log", pod, "--set", "no-colon-here")
			if err == nil {
				t.Fatalf("expected kmeshctl to reject a --set value without a ':', got no error, output: %s", out)
			}
			if !strings.Contains(out, "Invalid set flag") {
				t.Fatalf("expected output to explain the invalid --set flag, got: %s", out)
			}
		})
	})
}
