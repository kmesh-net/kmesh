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


// getLogOutput executes the "kmeshctl log" command with the provided arguments
// and returns its combined output.
func getLogOutputs(args ...string) (string, error) {
   // Prepend "log" as the first argument.
   cmdArgs := append([]string{"log"}, args...)
   cmd := exec.Command("kmeshctl", cmdArgs...)
   output, err := cmd.CombinedOutput()
   return string(output), err
}


// findKmeshPod locates a running Kmesh daemon pod in the "kmesh-system" namespace using the label "app=kmesh".
func findKmeshPods(t *testing.T) string {
   const namespace = "kmesh-system"
   const label = "app=kmesh"
   cmd := exec.Command("kubectl", "-n", namespace, "get", "pods", "-l", label, "-o", "jsonpath={.items[0].metadata.name}")
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


// waitForPodReady waits until the specified pod (in the "kmesh-system" namespace) reaches Running state.
func waitForPodReadys(t *testing.T, podName string) {
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


// verifyLogOutputHeader checks that the command output contains the expected header text.
func verifyLogOutputHeaders(t *testing.T, output, expectedHeader string) {
   scanner := bufio.NewScanner(strings.NewReader(output))
   found := false
   for scanner.Scan() {
       line := strings.TrimSpace(scanner.Text())
       if strings.Contains(line, expectedHeader) {
           found = true
           break
       }
   }
   if !found {
       t.Errorf("Expected output to contain header %q but it did not. Full output:\n%s", expectedHeader, output)
   }
}


// TestKmeshctlLog verifies the log command functionality.
func TestKmeshctlLog(t *testing.T) {
   // Step 1: Retrieve a Kmesh daemon pod.
   podName := findKmeshPods(t)
   // Step 2: Wait until the pod is Running.
   waitForPodReadys(t, podName)


   // Subtest: Get all loggers.
   t.Run("get-all-loggers", func(t *testing.T) {
       // This should print a list of logger names.
       // The GetLoggerNames function prints "Existing Loggers:" header.
       output, err := getLogOutputs(podName)
       if err != nil {
           t.Fatalf("Failed to get logger names: %v, output: %s", err, output)
       }
       t.Logf("Output of 'kmeshctl log %s':\n%s", podName, output)
       verifyLogOutputHeaders(t, output, "Existing Loggers:")
   })


   // Subtest: Get default logger's level.
   t.Run("get-default-logger-level", func(t *testing.T) {
       // This should print details for the default logger.
       output, err := getLogOutputs(podName, "default")
       if err != nil {
           t.Fatalf("Failed to get default logger level: %v, output: %s", err, output)
       }
       t.Logf("Output of 'kmeshctl log %s default':\n%s", podName, output)
       if !strings.Contains(output, "Logger Name:") || !strings.Contains(output, "Logger Level:") {
           t.Errorf("Expected output to contain 'Logger Name:' and 'Logger Level:', but got: %s", output)
       }
   })


   // Subtest: Set default logger's level to "debug" and verify.
   t.Run("set-default-logger-level", func(t *testing.T) {
       // Use --set flag to set default logger level.
       output, err := getLogOutputs(podName, "--set", "default:debug")
       if err != nil {
           t.Fatalf("Failed to set default logger level: %v, output: %s", err, output)
       }
       t.Logf("Output of 'kmeshctl log %s --set default:debug':\n%s", podName, output)
       // Optionally, check for a confirmation message. If not returned,
       // re-run the get default command to check the level.
       output2, err := getLogOutputs(podName, "default")
       if err != nil {
           t.Fatalf("Failed to get default logger level after setting: %v, output: %s", err, output2)
       }
       t.Logf("Output of 'kmeshctl log %s default' after setting:\n%s", podName, output2)
       // Assert that the output indicates the default logger level is now set to debug.
       if !strings.Contains(strings.ToLower(output2), "debug") {
           t.Errorf("Expected default logger level to be 'debug', but output was: %s", output2)
       }
   })
}
