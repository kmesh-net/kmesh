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

package kmeshctl_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/test/shell"
)

// TestKmeshctlAuthz verifies the kmeshctl authz (enable/disable/status) against a Kmesh Daemon pod.
func TestKmeshctlAuthz(t *testing.T) {
	// 1) Grab the first Kmesh daemon pod from the cluster:
	podName, err := getFirstKmeshPod()
	if err != nil {
		t.Fatalf("could not retrieve a kmesh daemon pod name: %v", err)
	}
	t.Logf("Using Kmesh daemon pod: %s", podName)

	// 2) Enable Authz on the Kmesh Daemon Pod
	t.Run("enable-authz", func(t *testing.T) {
		cmd := fmt.Sprintf("kmeshctl authz enable %s", podName)
		out, err := shell.Execute(true, cmd)
		if err != nil {
			t.Fatalf("failed to enable authz on pod %q: %v\noutput: %s", podName, err, out)
		}
		t.Logf("enable-authz output:\n%s", out)
	})

	// 3) Check that Authz is enabled
	t.Run("verify-authz-enabled", func(t *testing.T) {
		// Wait a moment for Kmesh Daemon to process.
		time.Sleep(2 * time.Second)

		cmd := fmt.Sprintf("kmeshctl authz status %s", podName)
		out, err := shell.Execute(true, cmd)
		if err != nil {
			t.Fatalf("failed to check authz status: %v\noutput: %s", err, out)
		}
		t.Logf("status output:\n%s", out)

		// We assume the status output includes "true" or "enabled" if authz is on.
		if !strings.Contains(out, "true") && !strings.Contains(strings.ToLower(out), "enabled") {
			t.Fatalf("expected authz to be enabled, got: %s", out)
		}
	})

	// 4) Disable Authz on the Kmesh Daemon Pod
	t.Run("disable-authz", func(t *testing.T) {
		cmd := fmt.Sprintf("kmeshctl authz disable %s", podName)
		out, err := shell.Execute(true, cmd)
		if err != nil {
			t.Fatalf("failed to disable authz on pod %q: %v\noutput: %s", podName, err, out)
		}
		t.Logf("disable-authz output:\n%s", out)
	})

	// 5) Check that Authz is disabled
	t.Run("verify-authz-disabled", func(t *testing.T) {
		// Wait a moment for Kmesh Daemon to process.
		time.Sleep(2 * time.Second)

		cmd := fmt.Sprintf("kmeshctl authz status %s", podName)
		out, err := shell.Execute(true, cmd)
		if err != nil {
			t.Fatalf("failed to check authz status: %v\noutput: %s", err, out)
		}
		t.Logf("status output:\n%s", out)

		// We assume the status output includes "false" or "disabled" if authz is off.
		if !strings.Contains(out, "false") && !strings.Contains(strings.ToLower(out), "disabled") {
			t.Fatalf("expected authz to be disabled, got: %s", out)
		}
	})
}

// getFirstKmeshPod uses kubectl to find the first Kmesh Daemon pod (label app=kmesh) in kmesh-system.
func getFirstKmeshPod() (string, error) {
	cmd := `kubectl get pods -n kmesh-system -l app=kmesh -o jsonpath='{.items[0].metadata.name}'`
	out, err := shell.Execute(true, cmd)
	if err != nil {
		return "", fmt.Errorf("error retrieving kmesh daemon pod name: %v", err)
	}
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return "", fmt.Errorf("no Kmesh daemon pod found in kmesh-system namespace")
	}
	return trimmed, nil
}
