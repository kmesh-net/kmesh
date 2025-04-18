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
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func runVersionCmd(args ...string) (string, error) {
	cmdArgs := append([]string{"version"}, args...)
	cmd := exec.Command("kmeshctl", cmdArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func findKmeshPod(t *testing.T) string {
	const ns = "kmesh-system"
	const label = "app=kmesh"
	cmd := exec.Command("kubectl", "-n", ns, "get", "pods",
		"-l", label, "-o", "jsonpath={.items[0].metadata.name}")
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		list := exec.Command("kubectl", "-n", ns, "get", "pods", "-o", "wide")
		all, _ := list.CombinedOutput()
		t.Fatalf("could not find pod with label %q: %v\nPods:\n%s", label, err, string(all))
	}
	name := strings.TrimSpace(string(out))
	t.Logf("Found Kmesh pod: %s", name)
	return name
}

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
	t.Fatalf("pod %s did not become Running in time", pod)
}

func TestKmeshctlVersion(t *testing.T) {
	pod := findKmeshPod(t)
	waitForPodRunning(t, pod)

	t.Run("client-and-daemon-summary", func(t *testing.T) {
		out, err := runVersionCmd()
		t.Logf("Output of 'kmeshctl version':\n%s", out)
		if err != nil {
			t.Fatalf("version command failed: %v", err)
		}
		if !strings.Contains(out, "client version:") {
			t.Errorf("expected 'client version:' in output, got:\n%s", out)
		}
		if !strings.Contains(out, "kmesh-daemon version:") {
			t.Errorf("expected 'kmesh-daemon version:' in output, got:\n%s", out)
		}
	})

	t.Run("daemon-version-json", func(t *testing.T) {
		out, err := runVersionCmd(pod)
		t.Logf("Output of 'kmeshctl version %s':\n%s", pod, out)
		if err != nil {
			t.Fatalf("version <pod> command failed: %v", err)
		}
		var info struct {
			GitVersion string `json:"GitVersion"`
			GitCommit  string `json:"GitCommit"`
		}
		if err := json.Unmarshal([]byte(out), &info); err != nil {
			t.Fatalf("invalid JSON output: %v", err)
		}
		if info.GitVersion == "" || info.GitCommit == "" {
			t.Errorf("expected non-empty GitVersion and GitCommit, got: %+v", info)
		}
	})
}

func runDumpCmd(args ...string) (string, error) {
	cmdArgs := append([]string{"dump"}, args...)
	cmd := exec.Command("kmeshctl", cmdArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
 }

func TestKmeshctlDump(t *testing.T) {
	pod := findKmeshPod(t)
	waitForPodRunning(t, pod)
 
 
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
 
 func runAccesslogCmd(args ...string) (string, error) {
	cmdArgs := append([]string{"monitoring"}, args...)
	cmd := exec.Command("kmeshctl", cmdArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
 }

 func TestKmeshctlAccesslog(t *testing.T) {
	pod := findKmeshPod(t)
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
 