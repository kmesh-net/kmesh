//go:build integ
// +build integ

/*
End-to-End Test for kmeshctl authz Commands in Kmesh.

This test performs the following steps:
1. Automatically retrieves a running Kmesh Daemon pod from the "kmesh-system" namespace.
2. Waits for the pod to become ready.
3. Enables authorization offloading using "kmeshctl authz enable <pod>".
4. Verifies the status using "kmeshctl authz status <pod>" (expecting enabled output).
5. Disables authorization using "kmeshctl authz disable <pod>".
6. Verifies the status again (expecting disabled output).

This test ensures that the authz commands work correctly on a live cluster.
*/

package kmesh

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/shell"
	"istio.io/istio/pkg/test/util/retry"
)

// getKmeshPod retrieves the name of a running Kmesh daemon pod in the kmesh-system namespace.
// It uses kubectl with a jsonpath query to return the first pod with label "app=kmesh".
func getKmeshPod() (string, error) {
	out, err := shell.Execute(true, "kubectl get pods -n kmesh-system -l app=kmesh -o jsonpath='{.items[0].metadata.name}'")
	if err != nil {
		return "", fmt.Errorf("failed to get kmesh pod: %v", err)
	}
	podName := strings.Trim(out, "'")
	if podName == "" {
		return "", fmt.Errorf("no kmesh pod found")
	}
	return podName, nil
}

// runKmeshCtl builds and executes a kmeshctl authz command with the provided arguments.
// It returns the command output (stdout) or an error.
func runKmeshCtl(pod string, args ...string) (string, error) {
	// Construct the command string, e.g., "kmeshctl authz enable <pod>"
	cmd := "kmeshctl authz " + strings.Join(args, " ") + " " + pod
	return shell.Execute(true, cmd)
}

func TestKmeshctlAuthz(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		var pod string
		var err error

		// --- Pod Detection and Readiness ---
		// Retry until we can fetch a Kmesh daemon pod from the kmesh-system namespace.
		err = retry.Until(func() bool {
			pod, err = getKmeshPod()
			if err != nil {
				t.Logf("Retrying getKmeshPod: %v", err)
				return false
			}
			// Additionally, use kubectl wait to ensure the pod is Ready.
			_, err = shell.Execute(true, "kubectl wait pod -n kmesh-system -l app=kmesh --for=condition=Ready --timeout=60s")
			if err != nil {
				t.Logf("Pod not yet ready: %v", err)
				return false
			}
			t.Logf("Found ready Kmesh pod: %s", pod)
			return true
		}, retry.Timeout(90*time.Second), retry.Delay(3*time.Second))
		if err != nil {
			t.Fatalf("Failed to retrieve a ready Kmesh pod: %v", err)
		}

		// --- Enable Authz ---
		t.Log("Enabling authz on the Kmesh pod...")
		enableOut, err := runKmeshCtl(pod, "enable")
		if err != nil {
			t.Fatalf("Failed to enable authz: %v", err)
		}
		t.Logf("Authz enable output: %s", enableOut)
		// Expect the output to indicate authz is enabled (case-insensitive check for "true" or "enabled").
		if !strings.Contains(strings.ToLower(enableOut), "true") && !strings.Contains(strings.ToLower(enableOut), "enabled") {
			t.Fatalf("Unexpected output from enable command: %s", enableOut)
		}

		// --- Verify Authz Enabled ---
		// Allow a brief wait for the daemon to update its status.
		time.Sleep(2 * time.Second)
		t.Log("Verifying authz status (expected to be enabled)...")
		statusOut, err := runKmeshCtl(pod, "status")
		if err != nil {
			t.Fatalf("Failed to get authz status: %v", err)
		}
		t.Logf("Authz status output after enable: %s", statusOut)
		if !strings.Contains(strings.ToLower(statusOut), "true") && !strings.Contains(strings.ToLower(statusOut), "enabled") {
			t.Fatalf("Authz status is not enabled as expected: %s", statusOut)
		}

		// --- Disable Authz ---
		t.Log("Disabling authz on the Kmesh pod...")
		disableOut, err := runKmeshCtl(pod, "disable")
		if err != nil {
			t.Fatalf("Failed to disable authz: %v", err)
		}
		t.Logf("Authz disable output: %s", disableOut)
		// Expect the disable output to indicate authz is disabled (look for "false" or "disabled").
		if !strings.Contains(strings.ToLower(disableOut), "false") && !strings.Contains(strings.ToLower(disableOut), "disabled") {
			t.Fatalf("Unexpected output from disable command: %s", disableOut)
		}

		// --- Verify Authz Disabled ---
		// Wait again briefly before checking status.
		time.Sleep(2 * time.Second)
		t.Log("Verifying authz status (expected to be disabled)...")
		statusOut, err = runKmeshCtl(pod, "status")
		if err != nil {
			t.Fatalf("Failed to get authz status after disable: %v", err)
		}
		t.Logf("Authz status output after disable: %s", statusOut)
		if !strings.Contains(strings.ToLower(statusOut), "false") && !strings.Contains(strings.ToLower(statusOut), "disabled") {
			t.Fatalf("Authz status is not disabled as expected: %s", statusOut)
		}

		t.Log("kmeshctl authz commands test passed successfully.")
	})
}
