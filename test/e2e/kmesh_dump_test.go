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
   "os/exec"
   "strings"
   "testing"
   "time"
)


// runDumpCmd runs "kmeshctl dump" with the provided args and returns combined output and error.
func runDumpCmd(args ...string) (string, error) {
   cmdArgs := append([]string{"dump"}, args...)
   cmd := exec.Command("kmeshctl", cmdArgs...)
   out, err := cmd.CombinedOutput()
   return string(out), err
}


// findKmeshPod locates one Kmesh daemon pod in the "kmesh-system" namespace with label "app=kmesh".
func findPods(t *testing.T) string {
   const ns = "kmesh-system"
   const label = "app=kmesh"
   cmd := exec.Command("kubectl", "-n", ns, "get", "pods",
       "-l", label, "-o", "jsonpath={.items[0].metadata.name}")
   out, err := cmd.Output()
   if err != nil || len(out) == 0 {
       // For debugging
       list := exec.Command("kubectl", "-n", ns, "get", "pods", "-o", "wide")
       all, _ := list.CombinedOutput()
       t.Fatalf("failed to find pod with label %q: %v\nPods:\n%s", label, err, string(all))
   }
   name := strings.TrimSpace(string(out))
   t.Logf("Found Kmesh pod: %s", name)
   return name
}


// waitForPodRunning waits until the specified pod is in Running phase.
func waitForPod(t *testing.T, pod string) {
   const ns = "kmesh-system"
   const retries = 20
   const delay = 2 * time.Second
   for i := 0; i < retries; i++ {
       cmd := exec.Command("kubectl", "-n", ns, "get", "pod", pod, "-o", "jsonpath={.status.phase}")
       out, err := cmd.Output()
       if err == nil && strings.EqualFold(strings.TrimSpace(string(out)), "Running") {
           t.Logf("Pod %s is Running", pod)
           return
       }
       time.Sleep(delay)
   }
   t.Fatalf("pod %s did not become Running in time", pod)
}


func TestKmeshctlDump(t *testing.T) {
   pod := findPods(t)
   waitForPod(t, pod)


   t.Run("kernel-native", func(t *testing.T) {
       out, err := runDumpCmd(pod, "kernel-native")
       t.Logf("Output of 'kmeshctl dump %s kernel-native':\n%s", pod, out)
       if err != nil {
           t.Fatalf("dump kernel-native failed: %v", err)
       }
       if strings.TrimSpace(out) == "" {
           t.Errorf("expected non-empty output for kernel-native, got empty")
       }
   })


   t.Run("dual-engine", func(t *testing.T) {
       out, err := runDumpCmd(pod, "dual-engine")
       t.Logf("Output of 'kmeshctl dump %s dual-engine':\n%s", pod, out)
       if err != nil {
           t.Fatalf("dump dual-engine failed: %v", err)
       }
       if strings.TrimSpace(out) == "" {
           t.Errorf("expected non-empty output for dual-engine, got empty")
       }
   })


   t.Run("invalid-mode", func(t *testing.T) {
       out, err := runDumpCmd(pod, "invalid-mode")
       t.Logf("Output of 'kmeshctl dump %s invalid-mode':\n%s", pod, out)
       if err == nil {
           t.Fatal("expected error for invalid mode, but command succeeded")
       }
       if !strings.Contains(out, "Argument must be 'kernel-native' or 'dual-engine'") {
           t.Errorf("expected error message about valid modes, got:\n%s", out)
       }
   })
}
