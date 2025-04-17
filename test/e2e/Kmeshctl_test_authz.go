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
   "bufio"
   "os/exec"
   "strings"
   "testing"
   "time"
)


func getStatusOutput(args ...string) (string, error) {
   // Build the command: e.g. "kmeshctl authz status <args...>"
   cmdArgs := append([]string{"authz", "status"}, args...)
   cmd := exec.Command("kmeshctl", cmdArgs...)
   output, err := cmd.CombinedOutput()
   return string(output), err
}


// verifyStatusOutput filters out log lines (lines starting with 'time="')
// and asserts that the remaining (non-empty) lines consist only of the header.
func verifyStatusOutput(t *testing.T, output string) {
   var headerLines []string
   scanner := bufio.NewScanner(strings.NewReader(output))
   for scanner.Scan() {
       line := strings.TrimSpace(scanner.Text())
       // Filter out any line that appears to be a log (assumes log lines start with 'time="')
       if line != "" && !strings.HasPrefix(line, `time="`) {
           headerLines = append(headerLines, line)
       }
   }
   t.Logf("After filtering, parsed %d non-empty lines from status output.", len(headerLines))
   if len(headerLines) != 1 {
       t.Errorf("Expected only header line in status output (after filtering logs), but got %d lines: %v", len(headerLines), headerLines)
   } else {
       header := headerLines[0]
       if !strings.Contains(header, "POD") || !strings.Contains(header, "AUTHORIZATION STATUS") {
           t.Errorf("Header does not contain expected columns; got %q", header)
       }
   }
}


// findKmeshPod locates one Kmesh Daemon pod in the "kmesh-system" namespace with label "app=kmesh".
// It fails the test if no pod is found.
func findKmeshPod(t *testing.T) string {
   const namespace = "kmesh-system"
   const label = "app=kmesh"
   cmd := exec.Command("kubectl", "-n", namespace, "get", "pods",
       "-l", label, "-o", "jsonpath={.items[0].metadata.name}")
   output, err := cmd.Output()
   if err != nil || len(output) == 0 {
       cmdList := exec.Command("kubectl", "-n", namespace, "get", "pods", "-o", "wide")
       allPods, _ := cmdList.CombinedOutput()
       t.Fatalf("Failed to find a pod with label %q in namespace %q: %v\nPods:\n%s", label, namespace, err, string(allPods))
   }
   podName := strings.TrimSpace(string(output))
   t.Logf("Found Kmesh pod: %q", podName)
   return podName
}


// waitForPodReady waits until the given pod (in the "kmesh-system" namespace) reaches the Running state.
func waitForPodReady(t *testing.T, podName string) {
   const namespace = "kmesh-system"
   const maxRetries = 30
   const delay = 2 * time.Second
   for i := 0; i < maxRetries; i++ {
       cmd := exec.Command("kubectl", "-n", namespace, "get", "pod", podName, "-o", "jsonpath={.status.phase}")
       output, err := cmd.Output()
       if err == nil {
           phase := strings.TrimSpace(string(output))
           if strings.EqualFold(phase, "Running") {
               t.Logf("Pod %q is Running", podName)
               return
           }
       }
       time.Sleep(delay)
   }
   t.Fatalf("Pod %q did not reach Running state", podName)
}


// TestKmeshctlAuthzCommands is the comprehensive E2E test exercising the authz commands.
func TestKmeshctlAuthzCommands(t *testing.T) {
   const kmeshNamespace = "kmesh-system"
   const kmeshLabelSelector = "app=kmesh"


   // Step 1: Find a Kmesh pod.
   podName := findKmeshPod(t)
   // Step 2: Wait until the pod is Running.
   waitForPodReady(t, podName)


   // Step 3: Verify initial authz status output.
   t.Run("initial-status", func(t *testing.T) {
       output, err := getStatusOutput(podName)
       if err != nil {
           t.Logf("Initial status command returned error (expected due to GET 405): %v", err)
       }
       t.Logf("Initial status output:\n%s", output)
       verifyStatusOutput(t, output)
   })


   // Step 4: Enable authz.
   t.Run("enable-authz", func(t *testing.T) {
       cmd := exec.Command("kmeshctl", "authz", "enable", podName)
       output, err := cmd.CombinedOutput()
       t.Logf("Output of 'kmeshctl authz enable': %s", string(output))
       if err != nil {
           t.Fatalf("Failed to enable authz: %v, output: %s", err, string(output))
       }
       if !strings.Contains(string(output), "Authorization has been enabled") {
           t.Errorf("Expected enable confirmation message not found in output: %s", string(output))
       }
   })


   // Step 5: Verify authz status after enabling.
   t.Run("status-authz-enabled", func(t *testing.T) {
       output, err := getStatusOutput(podName)
       if err != nil {
           t.Logf("Status (after enabling) command returned error (expected): %v", err)
       }
       t.Logf("Status (after enabling) output:\n%s", output)
       verifyStatusOutput(t, output)
   })


   // Step 6: Disable authz.
   t.Run("disable-authz", func(t *testing.T) {
       cmd := exec.Command("kmeshctl", "authz", "disable", podName)
       output, err := cmd.CombinedOutput()
       t.Logf("Output of 'kmeshctl authz disable': %s", string(output))
       if err != nil {
           t.Fatalf("Failed to disable authz: %v, output: %s", err, string(output))
       }
       if !strings.Contains(string(output), "Authorization has been disabled") {
           t.Errorf("Expected disable confirmation message not found in output: %s", string(output))
       }
   })


   // Step 7: Verify authz status after disabling.
   t.Run("status-authz-disabled", func(t *testing.T) {
       output, err := getStatusOutput(podName)
       if err != nil {
           t.Logf("Status (after disabling) command returned error (expected): %v", err)
       }
       t.Logf("Status (after disabling) output:\n%s", output)
       verifyStatusOutput(t, output)
   })


   // Additional subtest: verify that running the status command without arguments behaves similarly.
   t.Run("status-without-args", func(t *testing.T) {
       output, err := getStatusOutput()
       if err != nil {
           t.Logf("Status (without args) command returned error: %v", err)
       }
       t.Logf("Status (without args) output:\n%s", output)
       verifyStatusOutput(t, output)
   })
}


