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


// runAccesslogCmd runs "kmeshctl monitoring" with the given args and returns its combined output and error.
func runAccesslogCmd(args ...string) (string, error) {
   cmdArgs := append([]string{"monitoring"}, args...)
   cmd := exec.Command("kmeshctl", cmdArgs...)
   out, err := cmd.CombinedOutput()
   return string(out), err
}


// findKmeshPod returns the name of one running Kmesh daemon pod in kmesh-system with label app=kmesh.
func findPod(t *testing.T) string {
   const ns = "kmesh-system"
   const label = "app=kmesh"
   cmd := exec.Command("kubectl", "-n", ns, "get", "pods",
       "-l", label, "-o", "jsonpath={.items[0].metadata.name}")
   out, err := cmd.Output()
   if err != nil || len(out) == 0 {
       // Debug listing
       list := exec.Command("kubectl", "-n", ns, "get", "pods", "-o", "wide")
       all, _ := list.CombinedOutput()
       t.Fatalf("could not find pod with label %q: %v\nPods:\n%s", label, err, string(all))
   }
   name := strings.TrimSpace(string(out))
   t.Logf("Found Kmesh pod: %s", name)
   return name
}


// waitForPodRunning waits for the given pod to enter Running state.
func waitForPodRunning(t *testing.T, pod string) {
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
   t.Fatalf("pod %s did not become Running", pod)
}


func TestKmeshctlAccesslog(t *testing.T) {
   pod := findPod(t)
   waitForPodRunning(t, pod)


   t.Run("enable-on-pod", func(t *testing.T) {
       out, err := runAccesslogCmd(pod, "--accesslog", "enable")
       t.Logf("enable-on-pod output:\n%s", out)
       if err != nil {
           t.Fatalf("failed to enable accesslog on pod %s: %v", pod, err)
       }
   })


   t.Run("disable-on-pod", func(t *testing.T) {
       out, err := runAccesslogCmd(pod, "--accesslog", "disable")
       t.Logf("disable-on-pod output:\n%s", out)
       if err != nil {
           t.Fatalf("failed to disable accesslog on pod %s: %v", pod, err)
       }
   })


   t.Run("enable-cluster", func(t *testing.T) {
       out, err := runAccesslogCmd("--accesslog", "enable")
       t.Logf("enable-cluster output:\n%s", out)
       if err != nil {
           t.Fatalf("failed to enable accesslog cluster-wide: %v", err)
       }
   })


   t.Run("disable-cluster", func(t *testing.T) {
       out, err := runAccesslogCmd("--accesslog", "disable")
       t.Logf("disable-cluster output:\n%s", out)
       if err != nil {
           t.Fatalf("failed to disable accesslog cluster-wide: %v", err)
       }
   })
}


