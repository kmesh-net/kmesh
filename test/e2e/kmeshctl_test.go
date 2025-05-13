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
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kmesh.net/kmesh/ctl/utils"
)

const (
	kmeshNamespace    = "kmesh-system"
	waypointNamespace = "default"
	waypointName      = "waypoint"
	waitTimeout       = 90 * time.Second
)

var (
	// podName is set once in init() after all Kmesh pods are Ready.
	podName string
)

// runCtlCmd runs `kmeshctl <subcmd> [args...]` and returns the trimmed output or error.
func runCtlCmd(t *testing.T, subcmd string, args ...string) (string, error) {
	t.Helper()
	cmdArgs := append([]string{subcmd}, args...)
	cmd := exec.Command("kmeshctl", cmdArgs...)
	out, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	t.Logf(">>> kmeshctl %s: %s", strings.Join(cmdArgs, " "), outStr)
	return outStr, err
}

// Package‐level init ensures Kmesh is ready before any tests run.
func init() {
	// 1) Wait up to 2 minutes for all Kmesh pods to become Ready.
	wait := exec.Command("kubectl", "-n", kmeshNamespace, "wait",
		"--for=condition=Ready", "pod", "-l", "app=kmesh",
		"--timeout=2m",
	)
	if out, err := wait.CombinedOutput(); err != nil {
		panic(fmt.Sprintf("❌ timed out waiting for Kmesh pods: %v\n%s",
			err, string(out)))
	}

	// 2) Retrieve the name of the first Ready Kmesh pod.
	getPod := exec.Command("kubectl", "-n", kmeshNamespace, "get", "pods",
		"-l", "app=kmesh", "-o", "jsonpath={.items[0].metadata.name}")
	out, err := getPod.Output()
	if err != nil || len(out) == 0 {
		panic(fmt.Sprintf("❌ failed to find any Kmesh pod: %v\n%s",
			err, string(out)))
	}
	podName = strings.TrimSpace(string(out))
}

// --- Version tests ---

func TestKmeshctlVersion(t *testing.T) {
	t.Run("client-and-daemon-summary", func(t *testing.T) {
		out, err := runCtlCmd(t, "version")
		if err != nil {
			t.Fatalf("version command failed: %v", err)
		}
		if !strings.Contains(out, "client version:") {
			t.Errorf("expected 'client version:' in output\n%s", out)
		}
		if !strings.Contains(out, "kmesh-daemon version:") {
			t.Errorf("expected 'kmesh-daemon version:' in output\n%s", out)
		}
	})

	t.Run("daemon-version-json", func(t *testing.T) {
		out, err := runCtlCmd(t, "version", podName)
		if err != nil {
			t.Fatalf("version <pod> failed: %v", err)
		}
		var info struct {
			GitVersion string `json:"GitVersion"`
			GitCommit  string `json:"GitCommit"`
		}
		if err := json.Unmarshal([]byte(out), &info); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if info.GitVersion == "" || info.GitCommit == "" {
			t.Errorf("expected non-empty GitVersion and GitCommit, got %+v", info)
		}
	})
}

// --- Dump tests ---

func TestKmeshctlDump(t *testing.T) {
	t.Run("kernel-native", func(t *testing.T) {
		out, err := runCtlCmd(t, "dump", podName, "kernel-native")
		if strings.Contains(out, "Invalid Client Mode") {
			t.Log("kernel-native not supported; skipping")
			return
		}
		if err != nil {
			t.Fatalf("dump kernel-native failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, `"workloads"`) {
			t.Errorf("expected \"workloads\" in dump\n%s", out)
		}
		if !strings.Contains(out, `"services"`) {
			t.Errorf("expected \"services\" in dump\n%s", out)
		}
	})

	t.Run("dual-engine", func(t *testing.T) {
		out, err := runCtlCmd(t, "dump", podName, "dual-engine")
		if err != nil {
			t.Fatalf("dump dual-engine failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, `"workloads"`) || !strings.Contains(out, `"services"`) {
			t.Errorf("unexpected dump output:\n%s", out)
		}
	})

	t.Run("invalid-mode", func(t *testing.T) {
		out, err := runCtlCmd(t, "dump", podName, "bogus-mode")
		if err == nil {
			t.Fatal("expected error for invalid mode")
		}
		if !strings.Contains(out, "Argument must be") {
			t.Errorf("expected usage error, got:\n%s", out)
		}
	})
}

// --- Accesslog tests ---

func TestKmeshctlAccesslog(t *testing.T) {
	t.Run("pod-enable", func(t *testing.T) {
		if _, err := runCtlCmd(t, "monitoring", podName, "--accesslog", "enable"); err != nil {
			t.Fatalf("enable accesslog on pod failed: %v", err)
		}
	})
	t.Run("pod-disable", func(t *testing.T) {
		if _, err := runCtlCmd(t, "monitoring", podName, "--accesslog", "disable"); err != nil {
			t.Fatalf("disable accesslog on pod failed: %v", err)
		}
	})
	t.Run("cluster-enable", func(t *testing.T) {
		if _, err := runCtlCmd(t, "monitoring", "--accesslog", "enable"); err != nil {
			t.Fatalf("cluster-wide accesslog enable failed: %v", err)
		}
	})
	t.Run("cluster-disable", func(t *testing.T) {
		if _, err := runCtlCmd(t, "monitoring", "--accesslog", "disable"); err != nil {
			t.Fatalf("cluster-wide accesslog disable failed: %v", err)
		}
	})
}

// --- Log tests ---

// verifyLogHeader checks that output lines include the given header.
func verifyLogHeader(t *testing.T, output, header string) {
	t.Helper()
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), header) {
			return
		}
	}
	t.Errorf("missing header %q in log output:\n%s", header, output)
}

func TestKmeshctlLog(t *testing.T) {
	t.Run("list-loggers", func(t *testing.T) {
		out, err := runCtlCmd(t, "log", podName)
		if err != nil {
			t.Fatalf("list loggers failed: %v", err)
		}
		verifyLogHeader(t, out, "Existing Loggers:")
	})

	t.Run("get-default", func(t *testing.T) {
		out, err := runCtlCmd(t, "log", podName, "default")
		if err != nil {
			t.Fatalf("get default logger failed: %v", err)
		}
		if !strings.Contains(out, "Logger Name:") || !strings.Contains(out, "Logger Level:") {
			t.Errorf("unexpected get-default output:\n%s", out)
		}
	})

	t.Run("set-and-get-default", func(t *testing.T) {
		if _, err := runCtlCmd(t, "log", podName, "--set", "default:debug"); err != nil {
			t.Fatalf("set default to debug failed: %v", err)
		}
		out, err := runCtlCmd(t, "log", podName, "default")
		if err != nil {
			t.Fatalf("get default after set failed: %v", err)
		}
		if !strings.Contains(strings.ToLower(out), "debug") {
			t.Errorf("expected log level debug, got:\n%s", out)
		}
	})
}

// --- Secret tests ---

type ipSecKey struct {
	AeadKeyName string `json:"AeadKeyName"`
	AeadKey     []byte `json:"AeadKey"`
	Length      int    `json:"Length"`
	Spi         int    `json:"Spi"`
}

func waitForSecret(t *testing.T, name, ns string, timeout time.Duration) *v1.Secret {
	t.Helper()
	clientset, err := utils.CreateKubeClient()
	if err != nil {
		t.Fatalf("failed to create kube client: %v", err)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		sec, err := clientset.Kube().CoreV1().
			Secrets(ns).
			Get(context.TODO(), name, metav1.GetOptions{})
		if err == nil {
			return sec
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("timed out waiting for secret %q in %q", name, ns)
	return nil
}

func deleteSecret(t *testing.T, name, ns string) {
	t.Helper()
	clientset, err := utils.CreateKubeClient()
	if err != nil {
		t.Fatalf("failed to create kube client: %v", err)
	}
	_ = clientset.Kube().CoreV1().
		Secrets(ns).
		Delete(context.TODO(), name, metav1.DeleteOptions{})
}

func genRandomKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 36)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random key generation failed: %v", err)
	}
	return hex.EncodeToString(b)
}

func TestKmeshctlSecret(t *testing.T) {
	const secretName = "kmesh-ipsec"
	deleteSecret(t, secretName, kmeshNamespace)

	key1 := genRandomKey(t)
	t.Logf("Using key1=%s", key1)
	if _, err := runCtlCmd(t, "secret", "--key", key1); err != nil {
		t.Fatalf("first secret generate failed: %v", err)
	}
	sec1 := waitForSecret(t, secretName, kmeshNamespace, 30*time.Second)
	raw1 := sec1.Data["ipSec"]
	var k1 ipSecKey
	if err := json.Unmarshal(raw1, &k1); err != nil {
		t.Fatalf("unmarshal ipSec failed: %v", err)
	}
	if k1.Spi != 1 {
		t.Errorf("expected SPI=1 after create, got %d", k1.Spi)
	}

	key2 := genRandomKey(t)
	t.Logf("Using key2=%s", key2)
	if _, err := runCtlCmd(t, "secret", "--key", key2); err != nil {
		t.Fatalf("second secret generate failed: %v", err)
	}
	sec2 := waitForSecret(t, secretName, kmeshNamespace, 30*time.Second)
	raw2 := sec2.Data["ipSec"]
	var k2 ipSecKey
	if err := json.Unmarshal(raw2, &k2); err != nil {
		t.Fatalf("unmarshal updated ipSec failed: %v", err)
	}
	if k2.Spi != k1.Spi+1 {
		t.Errorf("expected SPI=%d after update, got %d", k1.Spi+1, k2.Spi)
	}
}

// --- Authz tests ---

func TestKmeshctlAuthz(t *testing.T) {
	t.Run("cluster-enable-disable", func(t *testing.T) {
		if _, err := runCtlCmd(t, "authz", "enable"); err != nil {
			t.Fatalf("authz enable failed: %v", err)
		}
		if _, err := runCtlCmd(t, "authz", "disable"); err != nil {
			t.Fatalf("authz disable failed: %v", err)
		}
	})

	t.Run("pod-enable-disable", func(t *testing.T) {
		if _, err := runCtlCmd(t, "authz", "enable", podName); err != nil {
			t.Fatalf("authz enable %s failed: %v", podName, err)
		}
		if _, err := runCtlCmd(t, "authz", "disable", podName); err != nil {
			t.Fatalf("authz disable %s failed: %v", podName, err)
		}
	})
}

// --- Waypoint tests ---

func TestKmeshctlWaypoint(t *testing.T) {
	t.Run("generate", func(t *testing.T) {
		out, err := runCtlCmd(t, "waypoint", "generate", "-n", waypointNamespace)
		if err != nil {
			t.Fatalf("generate failed: %v", err)
		}
		if !strings.Contains(out, "kind: Gateway") {
			t.Errorf("expected 'kind: Gateway', got:\n%s", out)
		}
	})

	t.Run("apply", func(t *testing.T) {
		out, err := runCtlCmd(t, "waypoint", "apply", "-n", waypointNamespace, "-w")
		if err != nil {
			t.Fatalf("apply failed: %v", err)
		}
		want := fmt.Sprintf("waypoint %s/%s applied", waypointNamespace, waypointName)
		if !strings.Contains(out, want) {
			t.Errorf("expected %q, got:\n%s", want, out)
		}
	})

	t.Run("list", func(t *testing.T) {
		// Poll for the waypoint to appear in the list
		found := false
		start := time.Now()
		for time.Since(start) < waitTimeout {
			out, err := runCtlCmd(t, "waypoint", "list", "-n", waypointNamespace)
			if err != nil {
				t.Logf("waypoint list error (retrying): %v", err)
			} else if strings.Contains(out, waypointName) {
				found = true
				break
			}
			time.Sleep(2 * time.Second)
		}
		if !found {
			t.Fatalf("expected %q in 'kmeshctl waypoint list' within %v", waypointName, waitTimeout)
		}
	})

	t.Run("status", func(t *testing.T) {
		out, err := runCtlCmd(t, "waypoint", "status", "-n", waypointNamespace)
		if err != nil {
			t.Fatalf("status failed: %v", err)
		}
		if !strings.Contains(out, "NAME") || !strings.Contains(out, "STATUS") {
			t.Errorf("expected headers in status, got:\n%s", out)
		}
	})

	t.Run("delete", func(t *testing.T) {
		out, err := runCtlCmd(t, "waypoint", "delete", "--all", "-n", waypointNamespace)
		if err != nil {
			t.Fatalf("delete failed: %v", err)
		}
		if !strings.Contains(out, fmt.Sprintf("waypoint %s/%s deleted", waypointNamespace, waypointName)) {
			t.Errorf("expected delete confirmation, got:\n%s", out)
		}
	})

	t.Run("list-after-delete", func(t *testing.T) {
		out, err := runCtlCmd(t, "waypoint", "list", "-n", waypointNamespace)
		if err != nil {
			t.Fatalf("list after delete failed: %v", err)
		}
		if !strings.Contains(out, "No waypoints found.") {
			t.Errorf("expected 'No waypoints found.', got:\n%s", out)
		}
	})
}
